# Thor Firewall — Makefile
.PHONY: help dev build push deploy-staging deploy-prod rollback status

help:
	@echo "Thor Firewall — Build & Deploy Commands"
	@echo ""
	@echo "  dev             Start local development environment"
	@echo "  build           Build all Docker images"
	@echo "  push            Push images to GHCR"
	@echo "  deploy-staging  Deploy to Kubernetes staging"
	@echo "  deploy-prod     Deploy to Kubernetes production"
	@echo "  ml-train        Start ML training pipeline"
	@echo "  compliance      Run compliance evaluation"
	@echo "  report          Generate compliance PDF report"
	@echo "  rollback        Rollback last deployment"
	@echo "  status          Check deployment status"

dev:
	docker compose up -d
	@echo "✅ Thor dev environment started"
	@echo "   Dashboard: http://localhost:3000"
	@echo "   API:       http://localhost:8000"
	@echo "   MLflow:    http://localhost:5000"
	@echo "   Grafana:   http://localhost:3001"

build:
	docker build -t ghcr.io/mhmsdfhwhegggggggg/thor-agent:latest ./agent
	docker build -t ghcr.io/mhmsdfhwhegggggggg/thor-control-plane:latest ./control-plane
	docker build -t ghcr.io/mhmsdfhwhegggggggg/thor-ml-inference:latest ./ml
	docker build -t ghcr.io/mhmsdfhwhegggggggg/thor-dashboard:latest ./dashboard

push: build
	docker push ghcr.io/mhmsdfhwhegggggggg/thor-agent:latest
	docker push ghcr.io/mhmsdfhwhegggggggg/thor-control-plane:latest
	docker push ghcr.io/mhmsdfhwhegggggggg/thor-ml-inference:latest
	docker push ghcr.io/mhmsdfhwhegggggggg/thor-dashboard:latest

deploy-staging:
	helm upgrade --install thor-staging ./helm/thor-firewall \
		-f helm/thor-firewall/values.yaml \
		-f helm/thor-firewall/values.dev.yaml \
		--namespace thor-staging \
		--create-namespace \
		--wait --timeout 5m

deploy-prod:
	@echo "⚠️  Deploying to PRODUCTION..."
	@read -p "Type 'yes-deploy' to confirm: " CONFIRM; [ "$$CONFIRM" = "yes-deploy" ] || exit 1
	helm upgrade --install thor ./helm/thor-firewall \
		-f helm/thor-firewall/values.yaml \
		-f helm/thor-firewall/values.production.yaml \
		--namespace thor-production \
		--create-namespace \
		--wait --timeout 10m
	@echo "✅ Production deployment complete"

ml-train:
	docker compose run --rm ml-training \
		python training/train_marl.py \
		--epochs 100 --batch-size 256 \
		--mlflow-uri http://mlflow:5000

ml-data:
	cd ml/data && bash download_cicids.sh ./raw
	cd ml && python data/preprocess.py --data-dir data/raw --output-dir data/processed

compliance:
	docker compose exec control-plane python -m src.compliance.evaluate

report:
	docker compose exec control-plane python -m src.reporting.generate_report --type soc2

rollback:
	helm rollback thor --namespace thor-production

status:
	kubectl get pods -n thor-production
	helm status thor -n thor-production
