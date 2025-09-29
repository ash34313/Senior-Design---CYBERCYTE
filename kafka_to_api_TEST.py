import os, asyncio, json, ssl
import random
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException
from kafka import KafkaConsumer, KafkaProducer
import asyncpg
from dotenv import load_dotenv
# Removed: from typing import Optional, Dict, Any # Using | None syntax now

# Configure using environment variables for connection security parameters
load_dotenv()
KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "osquery_logs")
KAFKA_CA_FILE = os.getenv("KAFKA_CA_FILE")
KAFKA_CERT_FILE = os.getenv("KAFKA_CERT_FILE")
KAFKA_KEY_FILE = os.getenv("KAFKA_KEY_FILE")

# Supabase/PostgreSQL Configuration
SUPABASE_DB_URL = os.getenv("SUPABASE_DB_URL", "postgresql://user:password@localhost:5432/postgres")
SUPABASE_CA_FILE = os.getenv("SUPABASE_CA_FILE")
SUPABASE_TABLE_NAME = "host_telemetry"

# --- Global Resources ---
db_pool: asyncpg.Pool | None = None
kafka_producer: KafkaProducer | None = None

# --- Mock Data Generation Function ---
def generate_mock_osquery_event(host_id: str):
    """Generates a mock osquery process event."""
    
    # Mock data to simulate osquery's scheduled query output (JSON structure)
    event_data = {
        "hostIdentifier": host_id,
        "name": "network_connections",
        "action": "added",
        "timestamp": int(datetime.now(timezone.utc).timestamp()),
        "columns": {
            "protocol": random.choice(["TCP", "UDP"]),
            "local_address": f"192.168.1.{random.randint(10, 200)}",
            "remote_address": f"203.0.113.{random.randint(10, 254)}",
            "local_port": random.randint(1024, 65535),
            "remote_port": random.choice([80, 443, 22, 3389]),
            "pid": random.randint(1000, 99999),
            "process_name": random.choice(["chrome", "ssh", "powershell", "curl"]),
        },
    }
    return event_data

# --- Kafka Consumer + PostgreSQL Logic ---
async def consume_kafka_messages():
    """Consumes messages from Kafka and saves them to Supabase (PostgreSQL)."""
    
    # Configure Kafka TLS/SSL 
    kafka_consumer_args = {
        'bootstrap_servers': KAFKA_BROKER,
        'value_deserializer': lambda v: json.loads(v.decode('utf-8')),
        'auto_offset_reset': 'latest',
        'enable_auto_commit': True,
        'group_id': 'fastapi-supabase-consumer',
    }
    
    # Add SSL parameters if environment variables are set
    if KAFKA_CA_FILE and KAFKA_CERT_FILE and KAFKA_KEY_FILE:
        kafka_consumer_args.update({
            'security_protocol': 'SSL',
            'ssl_context': ssl.create_default_context(cafile=KAFKA_CA_FILE),
            'ssl_check_hostname': False, 
            'ssl_certfile': KAFKA_CERT_FILE,
            'ssl_keyfile': KAFKA_KEY_FILE,
        })
    consumer = KafkaConsumer(KAFKA_TOPIC, **kafka_consumer_args)
    print("Starting Kafka consumer...")

    if not db_pool:
        print("Database connection pool not initialized. Cannot save data.")
        return

    # Check if the table exists (Optional, but good practice)
    async with db_pool.acquire() as connection:
        try:
            # We check for a column name that matches the payload column defined below.
            await connection.fetchval(f"SELECT column_name FROM information_schema.columns WHERE table_name = '{SUPABASE_TABLE_NAME}' AND column_name = 'payload'")
        except asyncpg.exceptions.UndefinedTableError:
            print(f"Warning: Table {SUPABASE_TABLE_NAME} does not exist. Please create it.")
            return

    for message in consumer:
        try:
            osquery_log_entry = message.value
            osquery_log_entry['timestamp_processed'] = datetime.utcnow()
            
            # Convert the dictionary data into a JSON string for the PostgreSQL JSONB column
            data_json = json.dumps(osquery_log_entry, default=str)

            # Insert the document into Supabase (PostgreSQL)
            async with db_pool.acquire() as connection:
                await connection.execute(
                    f"""
                    INSERT INTO {SUPABASE_TABLE_NAME} (payload, timestamp_processed)
                    VALUES ($1, $2)
                    """,
                    data_json,
                    osquery_log_entry['timestamp_processed']
                )
            print(f"Successfully saved document from host: {osquery_log_entry.get('hostIdentifier')}")
        except Exception as e:
            print(f"Error processing or saving message to Supabase: {e}")

# Manage FastAPI App Lifecycle
@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool, kafka_producer
    print("Connecting to Supabase (PostgreSQL)...")

    # --- 1. MongoDB/Supabase Connection Setup ---
    mongodb_client_args = {
        'uuidRepresentation': 'standard',
    }
    
    # Configure Supabase/PostgreSQL TLS/SSL 
    connect_args = {}
    if SUPABASE_CA_FILE:
        connect_args['ssl'] = ssl.create_default_context(cafile=SUPABASE_CA_FILE)
        
    # Initialize connection pool
    db_pool = await asyncpg.create_pool(
        SUPABASE_DB_URL,
        min_size=1, 
        max_size=10,
        **connect_args
    )
    print("Supabase connection established.")
    
    # --- 2. Kafka Producer Setup (Needed for Mock Data Generation) ---
    kafka_producer_args = {
        'bootstrap_servers': KAFKA_BROKER,
        'value_serializer': lambda v: json.dumps(v, default=str).encode('utf-8')
    }
    if KAFKA_CA_FILE and KAFKA_CERT_FILE and KAFKA_KEY_FILE:
         kafka_producer_args.update({
            'security_protocol': 'SSL',
            'ssl_context': ssl.create_default_context(cafile=KAFKA_CA_FILE),
            'ssl_certfile': KAFKA_CERT_FILE,
            'ssl_keyfile': KAFKA_KEY_FILE,
         })
    kafka_producer = KafkaProducer(**kafka_producer_args)
    print("Kafka Producer established.")


    # --- 3. Start Consumer Task ---
    task = asyncio.create_task(consume_kafka_messages())
    yield
    
    # Shutdown cleans up resources
    print("Closing connections...")
    await db_pool.close()
    kafka_producer.close() # Close the producer
    print("Database and Kafka Producer closed.")
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass # Expected during shutdown

# Initialize FastAPI 
app = FastAPI(lifespan=lifespan)

# --- API endpoints --- 

# New Mock Endpoint
@app.post("/mock/generate")
async def generate_mock_events(num_events: int = 5, host_id: str = "TestHost-Linux"):
    """
    Generates mock osquery events and publishes them directly to Kafka.
    This bypasses the need for a live osquery agent for testing.
    """
    if not kafka_producer:
        raise HTTPException(status_code=503, detail="Kafka Producer not initialized.")
    
    count = 0
    for _ in range(num_events):
        event = generate_mock_osquery_event(host_id)
        # Publish the event to the topic
        future = kafka_producer.send(KAFKA_TOPIC, value=event)
        try:
            future.get(timeout=10) # Wait for successful send
            count += 1
        except Exception as e:
            print(f"Failed to send mock message: {e}")
            raise HTTPException(status_code=500, detail="Failed to send mock data to Kafka")

    return {"status": "success", "message": f"Successfully published {count} mock events to Kafka topic '{KAFKA_TOPIC}'."}


@app.get("/telemetry")
async def get_all_telemetry():
    """Retrieves the latest telemetry data from Supabase (PostgreSQL)."""
    if not db_pool:
        raise HTTPException(status_code=503, detail="Database connection not available.")
    
    async with db_pool.acquire() as connection:
        results = await connection.fetch(
            f"""
            SELECT * FROM {SUPABASE_TABLE_NAME}
            ORDER BY timestamp_processed DESC
            LIMIT 100
            """
        )
    
    data = [dict(record) for record in results]
    return {"telemetry_data": data}

@app.get("/telemetry/count")
async def get_telemetry_count():
    """Returns the total number of telemetry documents in Supabase (PostgreSQL)."""
    if not db_pool:
        raise HTTPException(status_code=503, detail="Database connection not available.")
    
    async with db_pool.acquire() as connection:
        # fetchval is used to retrieve a single value (the count)
        count = await connection.fetchval(
            f"""
            SELECT COUNT(*) FROM {SUPABASE_TABLE_NAME}
            """
        )
    return {"count": count}