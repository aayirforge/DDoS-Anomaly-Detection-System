# Forwarding Makefile for DDoS Anomaly Detection System

TARGET_DIR := ddos-anomaly-detection-system

.PHONY: help setup download preprocess train train_rf train_knn train_lstm evaluate report capture convert live api dashboard test smoke clean

help:
	@$(MAKE) -C $(TARGET_DIR) help

setup:
	@$(MAKE) -C $(TARGET_DIR) setup

download:
	@$(MAKE) -C $(TARGET_DIR) download

preprocess:
	@$(MAKE) -C $(TARGET_DIR) preprocess

train:
	@$(MAKE) -C $(TARGET_DIR) train

train_rf:
	@$(MAKE) -C $(TARGET_DIR) train_rf

train_knn:
	@$(MAKE) -C $(TARGET_DIR) train_knn

train_lstm:
	@$(MAKE) -C $(TARGET_DIR) train_lstm

evaluate:
	@$(MAKE) -C $(TARGET_DIR) evaluate

report:
	@$(MAKE) -C $(TARGET_DIR) report

capture:
	@$(MAKE) -C $(TARGET_DIR) capture

convert:
	@$(MAKE) -C $(TARGET_DIR) convert

live:
	@$(MAKE) -C $(TARGET_DIR) live

api:
	@$(MAKE) -C $(TARGET_DIR) api

dashboard:
	@$(MAKE) -C $(TARGET_DIR) dashboard

test:
	@$(MAKE) -C $(TARGET_DIR) test

smoke:
	@$(MAKE) -C $(TARGET_DIR) smoke

clean:
	@$(MAKE) -C $(TARGET_DIR) clean
