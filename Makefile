.DEFAULT_GOAL := help

.PHONY: deploy
deploy: ## Deploy to Heroku
	@echo "+ $@"
	@git push heroku master

.PHONY: open
open: ## Deploy to Heroku
	@echo "+ $@"
	@heroku open

.PHONY: set-config
set-config: ## Set heroku config var
	@echo "+ $@"
	./set-config.sh

.PHONY: logs
logs: ## Set heroku config var
	@echo "+ $@"
	@heroku logs --tail

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'