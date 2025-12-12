# Numero massimo di processi
NUM_PROCESSES = 4
IS_CORRELATION = False
USE_GPU = True  # Cambia a False per disabilitare l'uso della GPU
GPU_PROCESSES = 3

# Stati delle task
STATE_PENDING = "pending"
STATE_IN_PROGRESS = "in_progress"
STATE_COMPLETED = "completed"
STATE_FAILED = "failed"

# Timeout predefiniti
LOCK_TIMEOUT = 10

# Parametri dei modelli AI
MODEL_PARAMETERS = {
    'SBERT': {
        'model_choice': 'mpnet',
        'batch_size': 64,
    },
    'ATTACKBERT': {
        'model_choice': 'attackbert',
        'batch_size': 16,
    },
}

# Altre costanti globali
MAX_RETRIES = 3
RETRY_DELAY = 5  # in secondi
