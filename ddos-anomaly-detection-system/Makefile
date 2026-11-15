.PHONY: help setup download preprocess train train_rf train_knn train_lstm evaluate report capture convert live api dashboard test smoke clean

PYTHON ?= .venv/bin/python
PIP ?= .venv/bin/pip
PYTEST ?= .venv/bin/pytest
STREAMLIT ?= .venv/bin/streamlit
UVICORN ?= .venv/bin/uvicorn

help:
	@echo "================================================================================"
	@echo "                   DDoS Anomaly Detection System (ddos_ads)"
	@echo "================================================================================"
	@echo "Available make targets:"
	@echo "  setup       - Create virtual environment and install dependencies"
	@echo "  download    - Download & validate raw dataset (manual or Kaggle)"
	@echo "  preprocess  - Clean, time-split, scale, and generate sequence windows"
	@echo "  train       - Train all 3 models (Random Forest, KNN, LSTM)"
	@echo "  train_rf    - Train Random Forest classifier"
	@echo "  train_knn   - Train K-Nearest Neighbors classifier"
	@echo "  train_lstm  - Train PyTorch LSTM sequence model"
	@echo "  evaluate    - Score trained models and generate benchmark plots"
	@echo "  capture     - Capture live packets to PCAP using tshark"
	@echo "  convert     - Extract flow statistics from PCAP via cicflowmeter"
	@echo "  live        - Start live detection daemon (default: alert-only)"
	@echo "  api         - Start FastAPI inference microservice"
	@echo "  dashboard   - Launch Streamlit interactive monitoring dashboard"
	@echo "  test        - Run offline unit and regression test suite"
	@echo "  smoke       - Run isolated training smoke tests on synthetic data"
	@echo "  clean       - Remove cache, temporary captures, and build artifacts"
	@echo "================================================================================"

setup:
	@echo "==> Creating virtual environment..."
	python3 -m venv .venv
	@echo "==> Installing dependencies..."
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) install -r requirements.txt
	$(PIP) install -e .
	@echo "==> Setup completed successfully."

download:
	PYTHONPATH=src $(PYTHON) -m ddos_ads.download_data --source manual

preprocess:
	PYTHONPATH=src $(PYTHON) -m ddos_ads.preprocess

train_rf:
	PYTHONPATH=src $(PYTHON) -m ddos_ads.train_rf

train_knn:
	PYTHONPATH=src $(PYTHON) -m ddos_ads.train_knn

train_lstm:
	PYTHONPATH=src $(PYTHON) -m ddos_ads.train_lstm

train: train_rf train_knn train_lstm
	@echo "==> All models trained successfully."

evaluate:
	PYTHONPATH=src $(PYTHON) -m ddos_ads.evaluate

report:
	PYTHONPATH=src $(PYTHON) -m ddos_ads.report

capture:
	PYTHONPATH=src $(PYTHON) -m ddos_ads.pcap_to_flows capture

convert:
	@if [ -z "$(PCAP)" ]; then \
		echo "Usage: make convert PCAP=path/to/capture.pcap"; \
		exit 1; \
	fi
	PYTHONPATH=src $(PYTHON) -m ddos_ads.pcap_to_flows convert --pcap $(PCAP)

live:
	PYTHONPATH=src $(PYTHON) -m ddos_ads.live_detector

api:
	PYTHONPATH=src $(PYTHON) -m ddos_ads.api

dashboard:
	PYTHONPATH=src $(STREAMLIT) run src/ddos_ads/dashboard.py

test:
	PYTHONPATH=src $(PYTEST) tests/ -v

smoke:
	PYTHONPATH=src $(PYTEST) tests/test_smoke_training.py -v

clean:
	rm -rf __pycache__ src/*/__pycache__ tests/__pycache__
	rm -rf .pytest_cache data/capture/*.pcap data/flows/*.csv
	find . -type f -name "*.pyc" -delete
