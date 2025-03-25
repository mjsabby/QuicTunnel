# QuicTunnel - SSH over QUIC Reverse Tunnel

QuicTunnel is a solution for SSH access to machines that don't have a public IP address. It uses QUIC protocol to establish and maintain resilient tunnels that can survive network changes and interruptions without breaking the SSH connection.

## Architecture

The system consists of three components:

1. **QuicTunnelRelay** - Central server with a public IP that relays traffic between clients and target machines.
2. **QuicTunnelReceiver** - Runs on the target machine (without a public IP) and connects to the relay server.
3. **QuicTunnelClient** - Used by SSH via ProxyCommand to connect to the target machine through the relay.

```
┌─────────────┐    QUIC    ┌─────────────┐    QUIC    ┌─────────────┐    TCP    ┌─────────────┐
│    SSH      │────────────│QuicTunnel   │────────────│QuicTunnel   │──────────│   SSH       │
│   Client    │            │   Client    │            │  Receiver   │          │  Server     │
└─────────────┘            └─────────────┘            └─────────────┘          └─────────────┘
                                │                           │                         
                                │                           │                         
                                ▼                           ▼                         
                          ┌─────────────────────────────────────┐                    
                          │           QuicTunnelRelay           │                    
                          │    (server with public IP)          │                    
                          └─────────────────────────────────────┘                    
```

## Diagram

![Diagram](./diagram.svg)

## Requirements

- .NET 9.0 or later
- TLS certificates for authentication
- A server with a public IP address for the relay
- SSH server running on the target machine

## Setup Instructions

### 1. Certificates

You need to create certificates for authentication:

```bash
# Generate server certificate for the relay
openssl req -x509 -newkey rsa:4096 -keyout server-key.pem -out server-cert.pem -days 365 -nodes
openssl pkcs12 -export -out server-cert.pfx -inkey server-key.pem -in server-cert.pem

# Generate client certificate for the client and receiver
openssl req -x509 -newkey rsa:4096 -keyout client-key.pem -out client-cert.pem -days 365 -nodes
openssl pkcs12 -export -out client-cert.pfx -inkey client-key.pem -in client-cert.pem
```

Place the generated PFX files in the appropriate directories for each component.

### 2. Building the Solution

```bash
# Clone the repository
git clone https://github.com/yourusername/quictunnel.git
cd quictunnel

# Build the solution
dotnet build

# Or build individual projects
dotnet build QuicTunnelRelay/QuicTunnelRelay.csproj
dotnet build QuicTunnelReceiver/QuicTunnelReceiver.csproj
dotnet build QuicTunnelClient/QuicTunnelClient.csproj
```

### 3. Configuration

Before running the components, update the following in each project:

- In `QuicTunnelRelay/Program.cs`: Update the path to the server certificate and password.
- In `QuicTunnelReceiver/Program.cs`: Update the relay server hostname/IP and the path to the client certificate.
- In `QuicTunnelClient/Program.cs`: Update the relay server hostname/IP and the path to the client certificate.

### 4. Deployment

1. **QuicTunnelRelay**:
   - Deploy to a server with a public IP address.
   - Ensure port 443 is open and accessible.
   - Run with: `dotnet run --project QuicTunnelRelay/QuicTunnelRelay.csproj`

2. **QuicTunnelReceiver**:
   - Deploy to the target machine (that doesn't have a public IP).
   - Ensure SSH server is running on port 22.
   - Run with: `dotnet run --project QuicTunnelReceiver/QuicTunnelReceiver.csproj`

3. **QuicTunnelClient**:
   - Deploy to the machine where you want to initiate SSH connections.
   - Configure SSH to use it as a ProxyCommand (see below).

### 5. SSH Configuration

Add the following to your SSH config file (`~/.ssh/config`):

```
Host target-machine
    HostName doesnt-matter
    User yourusername
    ProxyCommand path/to/QuicTunnelClient
```

## Usage Example

Once everything is set up, you can ssh to your target machine as usual:

```bash
ssh target-machine
```

The SSH client will use QuicTunnelClient as the proxy, which will connect to the relay server, which will forward the connection to the receiver, which will connect to the SSH server.

## Advanced Features

- **Connection Resumption**: QUIC supports connection resumption, allowing sessions to survive network changes.
- **Multiple Targets**: You can extend the system to support multiple target machines by implementing target identification.
- **Authentication**: The current implementation uses TLS client certificates for authentication. In a production environment, you should add additional authentication mechanisms.

## Security Considerations

- Always validate certificates in production.
- Consider implementing additional authentication mechanisms.
- Keep your certificates safe and use strong passwords.
- In production, implement proper logging and monitoring.

## License

[MIT License](LICENSE)
