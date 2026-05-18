### 🚀 Local Setup & Installation

**Prerequisites:**
* Python 3.11.x
* Git
* Docker Desktop

**1. Install Ollama**
* Download and install from https://ollama.com/download

**2. Clone the Repository**
```bash
git clone https://github.com/cle15102005/llm-based-threat-intelligence-gathering-system
cd llm-based-threat-intelligence-gathering-system
```

**3. Create and activate a Virtual Environment**
```bash
#Create
python3 -m venv venv

#Activate - Windows:
venv\Scripts\activate

#Activate - Mac / Linux:
source venv/bin/activate
```

**4. Install Project Dependencies**

With the environment activated, install the locked requirements:
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

**5. Verify the Environment**
```bash
pip check
```

**6. Pull the Local LLM Model for Reasoning and Embedding.**

We use `llama3` for report generation and `nomic-embed-text` for GraphRAG semantic search.
```bash
ollama pull llama3
ollama pull nomic-embed-text
```

**7. Install and Run Neo4j via Docker**
We use Neo4j to store and correlate threat actors, malware, and CVEs.
```bash
docker-compose up -d
```
Open http://localhost:7474 in your browser to access the Neo4j Query Console. 

**User:** `neo4j` | **Password:** `password`. 

**8. Configure Environment Variables**

Create a .env file in the root directory and add your API keys:
``` bash
NVD_API_KEY="your_key" #optional
OTX_API_KEY="your_key"
REDDIT_CLIENT_ID="your_id"
REDDIT_CLIENT_SECRET="your_secret"
REDDIT_USER_AGENT="ThreatIntel_Collector_v1.0"
NEO4J_PASSWORD="your_neo4j_password_here"
```

**9. Testing pipeline**
``` bash
python -m [unittest] tests.<test_module_name>  
```

