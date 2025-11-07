# FW Honeypot

## Deploy

```
# docker run --rm -it \
          -v $(pwd):/app \
          -v ~/.ssh:/root/.ssh:ro \
          -v /var/run/docker.sock:/var/run/docker.sock \
          -w /app \
          -e KAMAL_REGISTRY_PASSWORD=xxx \
          kamal-cli:latest \
          kamal deploy
```