# Experiments related to tuf-conformance testing

This is **very** early: there's barely anything here.

## Install

I suggest using a venv but anywhere works:
```
pip install -e .
```

## Run the test 

There's one half-written test runner for python-tuf ngclient.
The test suite contains one half implemented test.

Run that test:
python tuf_conformance/run_tests.py "python clients/python_tuf.py"
