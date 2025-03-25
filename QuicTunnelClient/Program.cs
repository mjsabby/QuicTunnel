namespace QuicTunnelClient
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net;
    using System.Net.Quic;
    using System.Net.Security;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;

    internal static class Program
    {
        private const int RelayPort = 443;

        private const string RelayHost = "your-relay-server.com"; // Replace with your relay server domain or IP

        private const string AlpnProtocol = "quic-tunnel-client";

        private const int BufferSize = 4096;

        private static readonly TextWriter StdErr = Console.Error;

        public static async Task Main(string[] args)
        {
            // Check platform compatibility
            if (!IsQuicSupported())
            {
                await StdErr.WriteLineAsync("Error: QUIC is not supported on this platform.").ConfigureAwait(false);
                await StdErr.WriteLineAsync("This tool requires Windows, Linux, or macOS.").ConfigureAwait(false);
                Environment.Exit(1);
                return;
            }
            
            try
            {
                if (args.Length > 0)
                {
                    await StdErr.WriteLineAsync("Usage: QuicTunnelClient").ConfigureAwait(false);
                    await StdErr.WriteLineAsync("Note: This tool is designed to be used as an SSH ProxyCommand").ConfigureAwait(false);
                    await StdErr.WriteLineAsync("Configuration:").ConfigureAwait(false);
                    await StdErr.WriteLineAsync($"  Relay Server: {RelayHost}:{RelayPort}").ConfigureAwait(false);
                    await StdErr.WriteLineAsync($"  ALPN Protocol: {AlpnProtocol}").ConfigureAwait(false);
                    await StdErr.WriteLineAsync("SSH Configuration Example:").ConfigureAwait(false);
                    await StdErr.WriteLineAsync("  Host quic-tunnel-example").ConfigureAwait(false);
                    await StdErr.WriteLineAsync("    ProxyCommand QuicTunnelClient").ConfigureAwait(false);
                    await StdErr.WriteLineAsync("    User your-username").ConfigureAwait(false);
                    await StdErr.WriteLineAsync("    IdentityFile ~/.ssh/id_rsa").ConfigureAwait(false);
                    return;
                }

                await StdErr.WriteLineAsync($"Connecting to QUIC relay server at {RelayHost}:{RelayPort}...").ConfigureAwait(false);
                
                // Check if certificate file exists, if not provide instructions
                if (!File.Exists("client-cert.pfx"))
                {
                    await StdErr.WriteLineAsync("Error: client-cert.pfx certificate file not found.").ConfigureAwait(false);
                    await StdErr.WriteLineAsync("Please create a client certificate and save it as 'client-cert.pfx' in the same directory.").ConfigureAwait(false);
                    await StdErr.WriteLineAsync("Example OpenSSL commands to create a self-signed certificate:").ConfigureAwait(false);
                    await StdErr.WriteLineAsync("  openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes").ConfigureAwait(false);
                    await StdErr.WriteLineAsync("  openssl pkcs12 -export -out client-cert.pfx -inkey key.pem -in cert.pem -passout pass:").ConfigureAwait(false);
                    Environment.Exit(1);
                    return;
                }

                using X509Certificate2 clientCertificate = new("client-cert.pfx", string.Empty);

                await ConnectAndForward(clientCertificate).ConfigureAwait(false);
            }
            catch (QuicException ex)
            {
                await StdErr.WriteLineAsync($"QUIC Error: {ex.Message}").ConfigureAwait(false);
                if (ex.InnerException != null)
                {
                    await StdErr.WriteLineAsync($"Inner Exception: {ex.InnerException.Message}").ConfigureAwait(false);
                }
                Environment.Exit(1);
            }
            catch (IOException ex)
            {
                await StdErr.WriteLineAsync($"I/O Error: {ex.Message}").ConfigureAwait(false);
                Environment.Exit(1);
            }
            catch (InvalidOperationException ex)
            {
                await StdErr.WriteLineAsync($"Operation Error: {ex.Message}").ConfigureAwait(false);
                Environment.Exit(1);
            }
            catch (SecurityException ex)
            {
                await StdErr.WriteLineAsync($"Security Error: {ex.Message}").ConfigureAwait(false);
                Environment.Exit(1);
            }
            catch (Exception ex) // Final fallback for unexpected errors
            {
                await StdErr.WriteLineAsync($"Unexpected Error: {ex.Message}").ConfigureAwait(false);
                if (ex.InnerException != null)
                {
                    await StdErr.WriteLineAsync($"Inner Exception: {ex.InnerException.Message}").ConfigureAwait(false);
                }
                throw; // Re-throw for debugging when run directly
            }
        }

        private static bool IsQuicSupported()
        {
            // QUIC is supported on Windows, Linux, and macOS
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ||
                   RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
                   RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        private static async Task ConnectAndForward(X509Certificate2 clientCertificate)
        {
            using var cts = new CancellationTokenSource();
            
            // Configure QUIC connection options
            var options = new QuicClientConnectionOptions
            {
                RemoteEndPoint = new IPEndPoint(
                    (await Dns.GetHostAddressesAsync(RelayHost).ConfigureAwait(false))[0], 
                    RelayPort),
                ClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    ApplicationProtocols = [new SslApplicationProtocol(AlpnProtocol)],
                    RemoteCertificateValidationCallback = (sender, certificate, chain, errors) => true, // Accept all certificates (for development)
                    ClientCertificates = [clientCertificate],
                }
            };

            await StdErr.WriteLineAsync("Establishing QUIC connection...").ConfigureAwait(false);

            QuicConnection connection = await QuicConnection.ConnectAsync(options, cts.Token).ConfigureAwait(false);
            await StdErr.WriteLineAsync("QUIC connection established.").ConfigureAwait(false);

            // Open a bidirectional stream for login and data transfer
            await StdErr.WriteLineAsync("Opening bidirectional stream...").ConfigureAwait(false);
            using var stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cts.Token).ConfigureAwait(false);
            await StdErr.WriteLineAsync("Stream opened. Sending login request...").ConfigureAwait(false);

            // Send login request
            string loginRequest = "LOGIN";
            await stream.WriteAsync(System.Text.Encoding.UTF8.GetBytes(loginRequest), cts.Token).ConfigureAwait(false);
            
            // Wait for login response
            var loginResponseBuffer = new byte[256];
            int bytesRead = await stream.ReadAsync(loginResponseBuffer, cts.Token).ConfigureAwait(false);
            string loginResponse = System.Text.Encoding.UTF8.GetString(loginResponseBuffer, 0, bytesRead);
            
            if (!loginResponse.StartsWith("OK", StringComparison.Ordinal))
            {
                await StdErr.WriteLineAsync($"Login failed: {loginResponse}").ConfigureAwait(false);
                return;
            }
            
            await StdErr.WriteLineAsync("Login successful. Starting data forwarding...").ConfigureAwait(false);
            
            // Start two tasks - one for reading from stdin and writing to QUIC stream
            // and another for reading from QUIC stream and writing to stdout
            var forwardStdinToQuic = ForwardStdinToQuicAsync(stream, cts.Token);
            var forwardQuicToStdout = ForwardQuicToStdoutAsync(stream, cts.Token);
            
            // Wait for both tasks to complete
            await Task.WhenAny(forwardStdinToQuic, forwardQuicToStdout).ConfigureAwait(false);
            
            // If one task completes, cancel the other to ensure clean shutdown
            await cts.CancelAsync().ConfigureAwait(false);
            
            try
            {
                await Task.WhenAll(forwardStdinToQuic, forwardQuicToStdout).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected when cancellation occurs
            }
            
            await StdErr.WriteLineAsync("Connection closed.").ConfigureAwait(false);
        }

        private static async Task ForwardStdinToQuicAsync(QuicStream stream, CancellationToken cancellationToken)
        {
            try
            {
                var buffer = new byte[BufferSize];
                using var stdin = Console.OpenStandardInput();
                
                while (!cancellationToken.IsCancellationRequested)
                {
                    // Read from stdin
                    int bytesRead = await stdin.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (bytesRead == 0) // End of stream
                    {
                        break;
                    }

                    // Write to QUIC stream
                    await stream.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Expected when cancellation occurs
            }
            catch (QuicException ex)
            {
                await StdErr.WriteLineAsync($"QUIC Error in stdin to QUIC forwarding: {ex.Message}").ConfigureAwait(false);
            }
            catch (IOException ex)
            {
                await StdErr.WriteLineAsync($"I/O Error in stdin to QUIC forwarding: {ex.Message}").ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await StdErr.WriteLineAsync($"Unexpected error in stdin to QUIC forwarding: {ex.Message}").ConfigureAwait(false);
                throw;
            }
        }

        private static async Task ForwardQuicToStdoutAsync(QuicStream stream, CancellationToken cancellationToken)
        {
            try
            {
                var buffer = new byte[BufferSize];
                using var stdout = Console.OpenStandardOutput();
                
                while (!cancellationToken.IsCancellationRequested)
                {
                    // Read from QUIC stream
                    int bytesRead = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (bytesRead == 0) // End of stream
                    {
                        break;
                    }

                    // Write to stdout
                    await stdout.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
                    await stdout.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Expected when cancellation occurs
            }
            catch (QuicException ex)
            {
                await StdErr.WriteLineAsync($"QUIC Error in QUIC to stdout forwarding: {ex.Message}").ConfigureAwait(false);
            }
            catch (IOException ex)
            {
                await StdErr.WriteLineAsync($"I/O Error in QUIC to stdout forwarding: {ex.Message}").ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await StdErr.WriteLineAsync($"Unexpected error in QUIC to stdout forwarding: {ex.Message}").ConfigureAwait(false);
                throw;
            }
        }
    }
}