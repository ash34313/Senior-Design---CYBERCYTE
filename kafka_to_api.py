import os, asyncio, json, ssl, asyncpg, time
from contextlib import asynccontextmanager
from datetime import datetime
from fastapi import FastAPI, HTTPException
from confluent_kafka import Consumer, KafkaException, OFFSET_BEGINNING
from dotenv import load_dotenv

# Configuration 
load_dotenv()
KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "osquery_logs")

# Confluent-Kafka requires specific C-style SSL configuration keys
KAFKA_CA_FILE = os.getenv("KAFKA_CA_FILE")       # ssl.ca.location
KAFKA_CERT_FILE = os.getenv("KAFKA_CERT_FILE")   # ssl.certificate.location
KAFKA_KEY_FILE = os.getenv("KAFKA_KEY_FILE")     # ssl.key.location

# Configure Supabase/PostgreSQL 
SUPABASE_DB_URL = os.getenv("SUPABASE_DB_URL", "postgresql://user:password@localhost:5432/postgres")
SUPABASE_CA_FILE = os.getenv("SUPABASE_CA_FILE")
SUPABASE_TABLE_NAME = "host_telemetry"

# Global state for shutdown and pool
db_pool: asyncpg.Pool | None = None
RUNNING = True

# Consumer & Write Logic
def run_kafka_consumer_in_thread(pool: asyncpg.Pool):
    """
    Synchronous function containing the Kafka Consumer poll loop.
    This must run in a separate thread using asyncio.to_thread() to avoid blocking.
    """
    global RUNNING

    # 1. CONFIGURE Confluent-Kafka (using C-style keys)
    kafka_config = {
        'bootstrap.servers': KAFKA_BROKER,
        'group.id': 'fastapi-supabase-consumer-group',
        'auto.offset.reset': 'latest',
        # Set poll timeout low to check RUNNING flag frequently
        'session.timeout.ms': 10000, 
    }
    
    # 2. ADD SSL/TLS Configuration
    if KAFKA_CA_FILE and KAFKA_CERT_FILE and KAFKA_KEY_FILE:
        kafka_config.update({
            'security.protocol': 'SSL',
            'ssl.ca.location': KAFKA_CA_FILE,
            'ssl.certificate.location': KAFKA_CERT_FILE,
            'ssl.key.location': KAFKA_KEY_FILE,
            # 'ssl.key.password': 'optional_password_here'
        })
    
    # 3. INITIALIZE Consumer
    try:
        consumer = Consumer(kafka_config)
        consumer.subscribe([KAFKA_TOPIC], on_assign=lambda c, ps: print(f"Assigned: {ps}"))
    except Exception as e:
        print(f"FATAL: Failed to initialize Kafka Consumer: {e}")
        return

    print(f"Kafka consumer started and subscribed to topic: {KAFKA_TOPIC}")

    # 4. CONSUMPTION LOOP
    while RUNNING:
        # poll() blocks for max 1.0 second, allowing graceful shutdown check
        msg = consumer.poll(1.0)
        
        if msg is None:
            continue
        
        if msg.error():
            if msg.error().code() == KafkaException._PARTITION_EOF:
                # End of partition event (normal behavior)
                continue
            elif msg.error():
                print(f"Kafka Consumer Error: {msg.error()}")
                # Consider backing off or breaking the loop based on error severity
                continue

        try:
            # Deserialize the value (Confluent Kafka returns raw bytes)
            # NOTE: Confluent client does not handle deserialization implicitly like kafka-python
            osquery_log_entry = json.loads(msg.value().decode('utf-8'))
            
            # Add processing timestamp
            osquery_log_entry['timestamp_processed'] = datetime.utcnow().isoformat()
            data_json = json.dumps(osquery_log_entry)

            # Write to Supabase (Database is async, so we must run it using the async loop)
            asyncio.run(
                save_telemetry_to_supabase(pool, data_json, osquery_log_entry.get('hostIdentifier'))
            )
            
        except json.JSONDecodeError as e:
            print(f"Error decoding message value: {e}. Message: {msg.value()}")
        except Exception as e:
            print(f"Unhandled error processing message: {e}")

    # 5. SHUTDOWN
    print("Stopping Kafka consumer...")
    consumer.close()
    print("Kafka consumer closed.")


async def save_telemetry_to_supabase(pool: asyncpg.Pool, data_json: str, host_identifier: str | None):
    """Handles the asynchronous database interaction."""
    try:
        async with pool.acquire() as connection:
            await connection.execute(
                f"""
                INSERT INTO {SUPABASE_TABLE_NAME} (payload)
                VALUES ($1::jsonb) 
                """,
                data_json
            )
        print(f"Successfully saved document from host: {host_identifier}")
    except asyncpg.exceptions.UndefinedTableError:
        print(f"Warning: Table {SUPABASE_TABLE_NAME} does not exist. Please create it.")
    except Exception as e:
        print(f"Error saving message to Supabase: {e}")

# --- FastAPI Lifecycle Management ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes database pool and starts the Kafka consumer thread."""
    global db_pool, RUNNING
    
    # 1. Database Initialization
    print("Connecting to Supabase (PostgreSQL)...")
    connect_args = {}
    if SUPABASE_CA_FILE:
        connect_args['ssl'] = ssl.create_default_context(cafile=SUPABASE_CA_FILE)
        
    try:
        db_pool = await asyncpg.create_pool(
            SUPABASE_DB_URL,
            min_size=1, 
            max_size=10,
            **connect_args
        )
        print("Supabase connection established.")
        
        # Check if table exists (optional, but good practice)
        async with db_pool.acquire() as connection:
            try:
                # Ensure the column type is correct for JSONB storage
                await connection.execute(f"SELECT 1 FROM {SUPABASE_TABLE_NAME} LIMIT 1")
            except asyncpg.exceptions.UndefinedTableError:
                print(f"WARNING: Table '{SUPABASE_TABLE_NAME}' does not exist.")
            
    except Exception as e:
        print(f"FATAL: Could not connect to Supabase: {e}")
        db_pool = None
        RUNNING = False # Stop startup if DB fails

    # 2. Kafka Consumer Background Task (using asyncio.to_thread)
    if RUNNING:
        # Run the synchronous consumer loop in a separate thread
        task = asyncio.create_task(asyncio.to_thread(run_kafka_consumer_in_thread, db_pool))
    
    yield
    
    # 3. Shutdown
    RUNNING = False
    if db_pool:
        print("Closing Supabase connection pool...")
        await db_pool.close()
        print("Supabase connection closed.")

    if RUNNING: # Only wait for task if it was successfully started
        try:
            await asyncio.wait_for(task, timeout=5.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            print("Kafka consumer thread shutdown.")

# Initialize FastAPI 
app = FastAPI(
    lifespan=lifespan,
    title="Kafka-Supabase Telemetry Ingestor",
    description="Ingests real-time telemetry from Kafka using confluent-kafka-python and stores it in Supabase/PostgreSQL."
)

# API Endpoints
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
    if not db_pool:
        raise HTTPException(status_code=503, detail="Database connection not available.")
    
    async with db_pool.acquire() as connection:
        count = await connection.fetchval(
            f"""
            SELECT COUNT(*) FROM {SUPABASE_TABLE_NAME}
            """
        )
    return {"count": count}