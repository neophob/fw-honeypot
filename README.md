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

- export stats via REST
- blacklist stuff - get rid off and use statistics
- parser tests
    2025-11-08T15:24:59.007Z SMB Data from 110.172.132.117: ff534d4272000000001801c8000000000000000000000000ffff000000000000002200024e54204c4d20302e31320002534d4220322e3030320002534d4220322e3f3f3f00

    2025-11-08T15:26:14.552Z SMB Data from 181.177.241.110: ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000

    2025-11-08T15:26:14.721Z SMB Data from 181.177.241.110: ff534d4275000000001807c00000000000000000000000000000fffe04ff400004ff005c00080001003100005c005c003100390032002e003100360038002e00350036002e00320030005c00490050004300240000003f3f3f3f3f00

    2025-11-08T15:21:51.989Z SMB Data from 201.219.168.242: ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200
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
