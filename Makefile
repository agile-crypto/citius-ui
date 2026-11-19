# citius-ui — Makefile
#
# Local stack (Zitadel + containerized citius-server) and UI. The container
# engine is detected when ENGINE is unset; force it with ENGINE=docker or
# ENGINE=podman. The logic lives in scripts.sh.

.PHONY: help start stop reset
.DEFAULT_GOAL := help

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

start: ## Check prerequisites, start the stack and the UI, print addresses and demo users
	@./scripts.sh start

stop: ## Stop the stack (keeps its data)
	@./scripts.sh stop

reset: ## Wipe the stack: data volumes, generated config and .env (make zitadel-nuke)
	@./scripts.sh reset
