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

## TODO

- blacklist stuff - get rid off and use statistics
- dump whole traffic and let a LLM decide, what this traffic was, what happended and how malicious it is
Analyze the traffic my honeypot received, figure out what the intent of this commands were in one short sentence ("Summary"). then print our color (red/yellow/green) depending on how evil/malicious the sent data is - where red is the worst

- hexdump

```
function hexdump(buffer, bytesPerLine = 16) {
  for (let i = 0; i < buffer.length; i += bytesPerLine) {
    const slice = buffer.slice(i, i + bytesPerLine);

    // Hex representation
    const hex = Array.from(slice)
      .map(b => b.toString(16).padStart(2, '0'))
      .join(' ');

    // ASCII representation
    const ascii = Array.from(slice)
      .map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
      .join('');

    // Print offset + hex + ASCII
    console.log(i.toString(16).padStart(8, '0'), hex.padEnd(bytesPerLine * 3), ascii);
  }
}
```
