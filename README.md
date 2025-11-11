# FW Honeypot

## Deploy

Make sure SSH connections work to the target, passwordless (`ssh-copy-id -i ~/.ssh/id_ed25519.pub -p PORT ubuntu@KAMALHOST`)

Install the kamal cli or use this fish shell script:

```
# cat ~/.config/fish/functions/kamal.fish
function kamal
    ssh-add
    docker run -it --rm \
        -v "$PWD:/workdir" \
        -v "$SSH_AUTH_SOCK:$SSH_AUTH_SOCK" \
        -e KAMAL_REGISTRY_PASSWORD \
        -e SSH_AUTH_SOCK="$SSH_AUTH_SOCK" \
        -v /var/run/docker.sock:/var/run/docker.sock \
       	-v "$HOME/.ssh/known_hosts:/root/.ssh/known_hosts:ro" \
        ghcr.io/basecamp/kamal:latest $argv
end
```
