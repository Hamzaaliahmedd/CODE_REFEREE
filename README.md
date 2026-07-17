High-Throughput Programmatic Code Evaluator

An automated system-safe testing framework built in Python. This tool is designed to dynamically parse, secure-scan, compile, and execute AI-generated code against strict logic constraints and edge cases. 

Key Features:
Static Security Guard: Scans raw code strings for malicious OS-level commands (e.g., `os.system`) before execution, acting as a system sandbox shield.
Dynamic Syntax Compilation: Checks for code compilability using Python's native compilation engine to instantly catch syntax errors without running the code. 
Isolated Execution (`exec`): Runs the code inside isolated namespaces to protect the parent application's global state.
Resilient Unit Testing: Runs test cases dynamically, intercepts standard output streams silently, and logs runtime exceptions (like `ZeroDivisionError`) without crashing the test harness.

How to Run This Project:

1. **Prerequisites**
You only need **Python 3.x** installed on your system. This project relies entirely on Python's built-in standard library—no external dependencies or installations required!

2. **Execution Instructions**
1 Clone this repository to your local machine:
```bash
git clone https://github.com/Hamzaaliahmedd/CODE_REFEREE
2 Navigate to the project directory:
Bash
cd CodeReferee
3 Run the evaluation script:
Bash
python eval_pipeline.py

3. **Modifying the Pipeline for New Code**
To test your own Python function dynamically:
Open eval_pipeline.py.
Add your custom function block to the MOCK_LLM_RESPONSES dictionary at the top of the file. 
