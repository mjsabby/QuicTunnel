namespace QuicTunnelReceiver
{
    using System;
    using System.Buffers;
    using System.Globalization;
    using System.IO;
    using System.Net;
    using System.Net.Quic;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    internal static class Program
    {
        private const string AlpnProtocol = "quic-tunnel-receiver";

        private const int BufferSize = 4096;

        public static async Task Main(string[] args)
        {
            if (args.Length != 3)
            {
                Console.WriteLine("Usage: QuicTunnelReceiver <RelayHost> <RelayPort> <ClientCertificatePath>");
                return;
            }

            string relayHost = args[0];
            int relayPort = int.Parse(args[1], CultureInfo.InvariantCulture);
            string clientCertificatePath = args[2];
            TimeSpan timeout = TimeSpan.FromSeconds(30);

            using X509Certificate2 clientCertificate = new(clientCertificatePath);

            await ConnectToRelayServer(relayHost, relayPort, timeout, clientCertificate).ConfigureAwait(false);
        }

        private static async Task ConnectToRelayServer(string relayHost, int relayPort, TimeSpan timeout, X509Certificate2 clientCertificate)
        {
            IPAddress relayServerIp = (await Dns.GetHostAddressesAsync(relayHost).ConfigureAwait(false))[0];
            
            var connectionOptions = new QuicClientConnectionOptions
            {
                RemoteEndPoint = new IPEndPoint(relayServerIp, relayPort),
                ClientAuthenticationOptions = new SslClientAuthenticationOptions { ApplicationProtocols = [new SslApplicationProtocol(AlpnProtocol)], ClientCertificates = [clientCertificate] },
                MaxInboundBidirectionalStreams = 10,
                DefaultStreamErrorCode = 1,
                DefaultCloseErrorCode = 1
            };
            
            using var cancellationSource = new CancellationTokenSource();
            
            QuicConnection connection = await QuicConnection.ConnectAsync(connectionOptions, cancellationSource.Token).ConfigureAwait(false);
            
            QuicStream controlStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).ConfigureAwait(false);
            _ = Task.Run(() => KeepControlStreamAliveAsync(controlStream, cancellationSource.Token));

            var streamAcceptTask = AcceptStreamsAsync(connection, timeout, cancellationSource.Token);
            
            try 
            {
                await streamAcceptTask.ConfigureAwait(false);
            }
            catch (QuicException ex)
            {
                Console.WriteLine($"Stream accept loop ended due to QUIC error: {ex.Message}");
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Stream accept loop ended: {ex.Message}");
                throw;
            }
        }

        private static async Task KeepControlStreamAliveAsync(QuicStream controlStream, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[BufferSize];
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    await WriteString(controlStream, "[ssh,rdp,smb]", buffer, cancellationToken).ConfigureAwait(false);
                    await controlStream.FlushAsync(cancellationToken).ConfigureAwait(false);

                    var timeoutTask = Task.Delay(TimeSpan.FromSeconds(60), cancellationToken);
                    var closureTask = controlStream.WritesClosed;
                    var completedTask = await Task.WhenAny(timeoutTask, closureTask).ConfigureAwait(false);

                    if (completedTask != timeoutTask)
                    {
                        break;
                    }
                }
            }
            catch (QuicException)
            {
                Console.WriteLine("Control stream connection closed.");
            }
            catch (IOException)
            {
                Console.WriteLine("Control stream I/O connection closed.");
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("Control stream monitoring was canceled.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error in control stream: {ex.Message}");
            }
        }
        
        private static async Task AcceptStreamsAsync(QuicConnection connection, TimeSpan timeout, CancellationToken cancellationToken)
        {
            ArrayPool<byte> shared = ArrayPool<byte>.Shared;
            byte[]? buffer = default;
            CancellationTokenSource? timeoutCts = default;
            CancellationTokenSource? linkedCts = default;

            try
            {
                buffer = shared.Rent(BufferSize);
                while (!cancellationToken.IsCancellationRequested)
                {
                    QuicStream quicStream = await connection.AcceptInboundStreamAsync(cancellationToken).ConfigureAwait(false);

                    timeoutCts = new(timeout);
                    linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
                    CancellationToken combinedToken = linkedCts.Token;

                    string? jwt = await ReadJWT(quicStream, buffer, combinedToken).ConfigureAwait(false);

                    if (jwt == null)
                    {
                        await quicStream.DisposeAsync().ConfigureAwait(false);
                        continue;
                    }

                    if (!VerifyJwt(jwt, out string host, out int port))
                    {
                        await quicStream.DisposeAsync().ConfigureAwait(false);
                        continue;
                    }

                    _ = Task.Run(() => HandleStreamAsync(quicStream, host, port, cancellationToken), cancellationToken);
                }
            }
            catch (QuicException ex)
            {
                Console.WriteLine($"QUIC error accepting streams: {ex.Message}");
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("Stream acceptance was canceled.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error accepting streams: {ex.Message}");
            }
            finally
            {
                if (buffer != null)
                {
                    shared.Return(buffer);
                }

                timeoutCts?.Dispose();
                linkedCts?.Dispose();
            }
        }

        private static async Task WriteString(QuicStream quicStream, string message, byte[] buffer, CancellationToken cancellationToken)
        {
            try
            {
                byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                int messageLength = messageBytes.Length;

                if (messageLength > BufferSize)
                {
                    throw new ArgumentOutOfRangeException(nameof(message), "Message is too large to send.");
                }

                BitConverter.GetBytes(messageLength).CopyTo(buffer, 0);
                await quicStream.WriteAsync(buffer.AsMemory(0, 4), cancellationToken).ConfigureAwait(false);

                messageBytes.CopyTo(buffer, 0);
                await quicStream.WriteAsync(buffer.AsMemory(0, messageLength), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Handle cancellation
            }
            catch (QuicException)
            {
                // Handle QUIC-specific errors
            }
            catch (IOException)
            {
                // Handle IO errors
            }
        }

        private static async Task<string?> ReadJWT(QuicStream quicStream, byte[] buffer, CancellationToken cancellationToken)
        {
            try
            {
                await quicStream.ReadAsync(buffer.AsMemory(0, 4), cancellationToken).ConfigureAwait(false);
                int jwtLength = BitConverter.ToInt32(buffer, 0);

                if (jwtLength <= 0 || jwtLength > BufferSize)
                {
                    return null;
                }

                await quicStream.ReadAsync(buffer.AsMemory(0, jwtLength), cancellationToken).ConfigureAwait(false);

                string jwt = Encoding.UTF8.GetString(buffer, 0, jwtLength);
                return jwt;
            }
            catch (OperationCanceledException)
            {
                return null;
            }
            catch (QuicException)
            {
                return null;
            }
            catch (IOException)
            {
                return null;
            }
        }
        
        private static async Task HandleStreamAsync(QuicStream quicStream, string host, int port, CancellationToken cancellationToken)
        {
            TcpClient? tcpClient = null;
            NetworkStream? tcpStream = null;
            
            try
            {
                tcpClient = new TcpClient();
                await tcpClient.ConnectAsync(host, port).ConfigureAwait(false);
                tcpStream = tcpClient.GetStream();
                
                var quicToSsh = ForwardDataAsync(quicStream, tcpStream, cancellationToken);
                var sshToQuic = ForwardDataAsync(tcpStream, quicStream, cancellationToken);
                
                await Task.WhenAny(quicToSsh, sshToQuic).ConfigureAwait(false);
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"SSH connection error: {ex.Message}");
            }
            catch (QuicException ex)
            {
                Console.WriteLine($"QUIC stream error: {ex.Message}");
            }
            catch (IOException ex)
            {
                Console.WriteLine($"IO error in stream handling: {ex.Message}");
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("Stream handling was canceled.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error handling stream: {ex.Message}");
            }
            finally
            {
                if (tcpStream != null)
                {
                    await tcpStream.DisposeAsync().ConfigureAwait(false);
                }
                
                tcpClient?.Dispose();
                
                await quicStream.DisposeAsync().ConfigureAwait(false);
            }
        }

        private static async Task ForwardDataAsync(Stream source, Stream destination, CancellationToken cancellationToken)
        {
            ArrayPool<byte> shared = ArrayPool<byte>.Shared;
            byte[]? buffer = default;
            try
            {
                buffer = shared.Rent(BufferSize);
                while (!cancellationToken.IsCancellationRequested)
                {
                    int bytesRead = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
                    if (bytesRead == 0)
                    {
                        break;
                    }
                    
                    await destination.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
                    await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            catch (QuicException ex)
            {
                Console.WriteLine($"QUIC error forwarding data: {ex.Message}");
            }
            catch (IOException ex)
            {
                Console.WriteLine($"IO error forwarding data: {ex.Message}");
            }
            catch (ObjectDisposedException ex)
            {
                Console.WriteLine($"Stream was disposed during forwarding: {ex.Message}");
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("Data forwarding was canceled.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error forwarding data: {ex.Message}");
            }
            finally
            {
                if (buffer != null)
                {
                    shared.Return(buffer);
                }
            }
        }

        private static bool VerifyJwt(string jwt, out string host, out int port)
        {
            _ = Base64UrlDecode(jwt);
            host = "linux.mshome.net";
            port = 22;
            return true;
        }

        private static byte[] Base64UrlDecode(string input)
        {
            string base64 = input.Replace('-', '+').Replace('_', '/');
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }

            return Convert.FromBase64String(base64);
        }
    }
}