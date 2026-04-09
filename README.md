### 🚀 Local Setup & Installation

**Prerequisites:**
* Python 3.11+
* Git

**1. Install Ollama**
* Download and install from https://ollama.com/download

**2. Clone the Repository**
```bash
git clone https://github.com/cle15102005/llm-based-threat-intelligence-gathering-system
cd llm-based-threat-intelligence-gathering-system
```

**3. Create a Virtual Environment**
```bash
python3 -m venv venv
```

**4. Activate the Virtual Environment**
* **Windows:**
  ```bash
  venv\Scripts\activate
  ```
* **Mac / Linux:**
  ```bash
  source venv/bin/activate
  ```
*(Note: You should see `(venv)` appear at the beginning of your terminal prompt).*

**5. Install Project Dependencies**
With the environment activated, install the locked requirements:
```bash
pip install -r requirements.txt
```

**6. Download Required NLP Models**
```bash
python -m spacy download en_core_web_sm
```

**7. Verify the Environment**
```bash
pip check
```
If the terminal returns `No broken requirements found.`, your Python environment is ready!

**8. Pull the Local LLM Model**
```bash
ollama pull llama3
```