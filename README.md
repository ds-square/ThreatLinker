# Threatlinker

Threatlinker is a Django-based project aimed at correlating Common Vulnerabilities and Exposures (CVE) with Common Attack Pattern Enumeration and Classification (CAPEC) attack patterns. This project seeks to streamline the process of identifying relationships between known vulnerabilities and attack patterns, enhancing threat intelligence analysis for cybersecurity professionals.

## Versions used in development

- **Python**: 3.11.8
- **Django**: 5.1.2
- **PostgreSQL**: 14
- **Memurai** (Windows) 4.14 / **Redis** (Linux)

## Versions Links for Windows Systems

- **Python** 3.11.8: https://www.python.org/downloads/release/python-3118/
- **PostgreSQL** 14: https://www.enterprisedb.com/downloads/postgres-postgresql-downloads
- **Memurai for Redis** 4.14: https://www.memurai.com/get-memurai


### Installing PyTorch with CUDA

**CUDA** (Compute Unified Device Architecture) is a parallel computing platform and programming model created by NVIDIA. It allows PyTorch to perform computations on NVIDIA GPUs, significantly speeding up tasks such as training and inference for deep learning models.

If you have an NVIDIA GPU and CUDA installed on your machine, you can enable PyTorch to utilize GPU acceleration by installing a CUDA-compatible version of `torch`. 

**Note:** CUDA is only compatible with NVIDIA GPUs. If you don’t have an NVIDIA GPU, you can skip this step and install the default CPU-only version of PyTorch.

#### Installation Instructions:
To check your CUDA version, run:

```bash
nvcc --version
```

Once you know your CUDA version, install PyTorch with CUDA support using the following command:

```bash
# Replace `cu118` with your specific CUDA version, e.g., cu117 for CUDA 11.7, cu116 for CUDA 11.6, etc.
pip install torch --index-url https://download.pytorch.org/whl/cu118
```

For more details on PyTorch installation options, visit the [official PyTorch installation page](https://pytorch.org/get-started/locally/).


## Project Structure

The project is structured as follows:

- **Django Framework**: Django is a high-level Python web framework that encourages rapid development and clean, pragmatic design. It handles much of the complexity in web development, providing built-in tools for database management, form handling, authentication, and more. In this project, Django is the backbone that integrates and serves data, manages URL routing, and enables interaction between the different modules related to CVE, CWE, and CAPEC data.

- **PostgreSQL**: PostgreSQL is a powerful, open-source object-relational database system that is used as the primary database for storing CVE, CWE, and CAPEC data in Threatlinker. It provides advanced indexing, data integrity, and supports JSON fields, making it an ideal choice for efficiently handling the complex relationships and structured data this project requires.

- **Memurai or Redis**: Memurai (for Windows) or Redis (for Linux) serves as the message broker and task queue backend for Celery in this project. It handles asynchronous tasks, allowing us to process data updates, such as importing and updating CVE, CWE, and CAPEC records, without blocking the main application’s performance. This is essential for managing the background tasks required by the application, ensuring smooth and efficient data processing.

- **Virtual Environment**: A Python virtual environment is set up to manage dependencies and maintain isolation from other projects, ensuring compatibility across different setups.

- **Git Integration**: The project is managed using Git and hosted on GitHub for version control, allowing for collaborative development, tracking changes, and maintaining code history.

## App Structure

The Threatlinker project is organized into four main applications, each with specific roles:

- **Core**: Responsible for implementing correlation functionalities, AI-based textual similarity using various techniques, text preprocessing, and process parallelization.
- **Data**: Manages data handling, updates, and the creation of models for CVE, CWE, CAPEC, and MITRE ATT&CK, including mechanisms to keep data current.
- **Graph**: Focuses on the graph representation of entities and their connections, providing a visual and structural perspective of relationships.
- **View**: Handles the display of other parts of the application not directly connected to the core functionalities.

## Installation

0. Set up the PostgreSQL database:
    
    - Access PostgreSQL as the default `postgres` user:
      ```bash
      psql -U postgres
      ```
    - If already exists:
      ```sql
      DROP DATABASE IF EXISTS threatlinker_db;
      DROP USER IF EXISTS threatlinker_user;
      ```
    - Create the database and user for the project:
      ```sql
      CREATE DATABASE threatlinker_db;
      CREATE USER threatlinker_user WITH PASSWORD 'threatlinkerpwd';
      GRANT ALL PRIVILEGES ON DATABASE threatlinker_db TO threatlinker_user;
      ```
    - Exit PostgreSQL:
      ```sql
      \q
      ```

1. Clone the repository:
    ```bash
    git clone https://github.com/andreaciavotta/threatlinker.git
    cd threatlinker
    ```

2. Create a virtual environment and activate it:

    - Windows:
      ```bash
      python -m venv .venv
      .venv\Scripts\activate
      ```

    - Linux/macOS:
      ```bash
      python3 -m venv .venv
      source .venv/bin/activate
      ```

3. Install required dependencies (on Windows):
    ```bash
    install_windows.bat
    ```

    Please look at the CUDA dependencies if you have nVidia.
    If needed first use:

    ```bash
    pip cache purge
    ```

4. Run migrations:
    ```bash
    python manage.py migrate
    ```

5. Create an admin (superuser) account:
    To access the Django admin interface, you need to create a superuser. Run:
    ```bash
    python manage.py createsuperuser
    ```
    Follow the prompts to set up a username, email, and password for the superuser.

6. Start the development server with parallel processes:
    ```bash
    python run_windows.py
    ```

   (For Linux, a similar script can be created to streamline startup.)

## Usage

Once the server is running, navigate to `http://127.0.0.1:8000` in your browser to access the application.

## Development

To contribute to this project:
1. Create a new branch for your feature or bugfix.
2. Make changes and test them thoroughly.
3. Push your branch to GitHub and open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
