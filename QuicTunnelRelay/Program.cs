namespace QuicTunnelRelay
{
    using System;
    using System.Buffers;
    using System.Collections.Concurrent;
    using System.IO;
    using System.Net;
    using System.Net.Quic;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    internal sealed class State
    {
        public string? Caps { get; set; }

        public QuicConnection? Client { get; set; }

        public QuicConnection? Receiver { get; set; }

        public CancellationTokenSource? Cancellation { get; set; }
    }

    internal static class Program
    {
        private const int BufferSize = 4096;

        private static readonly ConcurrentDictionary<string, State> ActivePairs = new();

        private static readonly X509Certificate2 ServerCertificate = new("C:/users/muks/downloads/localhost.muks.dev.pfx", string.Empty);

        private static readonly SslApplicationProtocol ReceiverAlpn = new("quic-tunnel-receiver");

        private static readonly SslApplicationProtocol ClientAlpn = new("quic-tunnel-client");

        public static async Task Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Usage: QuicTunnelRelay <ip> <port>");
                return;
            }

            if (!IPAddress.TryParse(args[0], out IPAddress? ip))
            {
                Console.WriteLine("Invalid IP address.");
                return;
            }

            if (!int.TryParse(args[1], out int relayPort))
            {
                Console.WriteLine("Invalid port number.");
                return;
            }

            using CancellationTokenSource cancellationTokenSource = new();
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                cancellationTokenSource.Cancel();
            };

            var cancellationToken = cancellationTokenSource.Token;

            QuicListenerOptions options = new()
            {
                ListenEndPoint = new IPEndPoint(ip, relayPort),
                ApplicationProtocols = [ClientAlpn, ReceiverAlpn],
                ConnectionOptionsCallback = GetConnectionOptions
            };

            QuicListener listener = await QuicListener.ListenAsync(options, cancellationToken).ConfigureAwait(false);

            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    QuicConnection connection = await listener.AcceptConnectionAsync(cancellationToken).ConfigureAwait(false);
                    Console.WriteLine($"Accepted connection from {connection.RemoteEndPoint} for {connection.TargetHostName}");
                    _ = AcceptConnectionsAsync(connection, cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error accepting connections: {ex.Message}");
            }

        }

        private static async Task<string?> ReadString(QuicStream quicStream, byte[] buffer, CancellationToken cancellationToken)
        {
            try
            {
                await quicStream.ReadAsync(buffer.AsMemory(0, 4), cancellationToken).ConfigureAwait(false);
                int stringLength = BitConverter.ToInt32(buffer, 0);

                if (stringLength <= 0 || stringLength > BufferSize)
                {
                    return null;
                }

                await quicStream.ReadAsync(buffer.AsMemory(0, stringLength), cancellationToken).ConfigureAwait(false);

                return Encoding.UTF8.GetString(buffer, 0, stringLength);
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

        private static async Task AcceptConnectionsAsync(QuicConnection clientConnection, CancellationToken cancellationToken)
        {
            string[] parts = clientConnection.TargetHostName.Split('.');
            if (parts.Length < 2)
            {
                throw new ArgumentException("Invalid host name format");
            }

            string host = parts[0];
            string type = parts[1];

            SslApplicationProtocol alpn = clientConnection.NegotiatedApplicationProtocol;

            if (alpn == ReceiverAlpn)
            {
                QuicStream? controlStream = await clientConnection.AcceptInboundStreamAsync(cancellationToken).ConfigureAwait(false) ?? throw new InvalidOperationException("Control stream is null");
                ArrayPool<byte> shared = ArrayPool<byte>.Shared;
                byte[]? buffer = default;

                try
                {
                    buffer = shared.Rent(BufferSize);
                    string? caps = await ReadString(controlStream, buffer, cancellationToken).ConfigureAwait(false);

                    if (string.IsNullOrEmpty(caps))
                    {
                        throw new InvalidOperationException("Caps is null or empty");
                    }

                    Console.WriteLine($"Receiver caps: {caps}");

                    var state = new State
                    {
                        Caps = caps,
                        Receiver = clientConnection,
                        Cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken)
                    };

                    ActivePairs[host] = state;

                    while (!cancellationToken.IsCancellationRequested)
                    {
                        string? message = await ReadString(controlStream, buffer, cancellationToken).ConfigureAwait(false);
                        if (string.IsNullOrEmpty(message))
                        {
                            break;
                        }

                        Console.WriteLine($"Receiver message: {message}");
                    }
                }
                finally
                {
                    if (buffer != null)
                    {
                        shared.Return(buffer);
                    }
                }
            }
            else if (alpn == ClientAlpn)
            {
                if (!ActivePairs.TryGetValue(host, out var state))
                {
                    throw new InvalidOperationException($"No active pair found for host: {host}");
                }

                var receiverConnection = state.Receiver ?? throw new InvalidOperationException($"Receiver connection is null for host: {host}");
                ArrayPool<byte> shared = ArrayPool<byte>.Shared;
                byte[]? buffer = default;
                QuicStream? receiverStream = await receiverConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken).ConfigureAwait(false);

                try
                {
                    buffer = shared.Rent(BufferSize);
                    await WriteString(receiverStream, "JWT + type", buffer, cancellationToken).ConfigureAwait(false);

                    while (!cancellationToken.IsCancellationRequested)
                    {
                        var clientStream = await clientConnection.AcceptInboundStreamAsync(cancellationToken).ConfigureAwait(false);
                        Console.WriteLine($"Accepted stream from client: Type={clientStream.Type}, ID={clientStream.Id}");

                        if (clientStream == null)
                        {
                            break;
                        }

                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                await ForwardDataAsync(clientStream, receiverStream, cancellationToken).ConfigureAwait(false);
                            }
                            finally
                            {
                                await clientStream.DisposeAsync().ConfigureAwait(false);
                            }
                        }, cancellationToken);
                    }
                }
                finally
                {
                    if (buffer != null)
                    {
                        shared.Return(buffer);
                    }
                }

            }
            else
            {
                throw new InvalidOperationException($"Unknown ALPN: {alpn}");
            }
        }

        private static ValueTask<QuicServerConnectionOptions> GetConnectionOptions(QuicConnection connection, SslClientHelloInfo clientHelloInfo, CancellationToken cancellationToken)
        {
            var options = new QuicServerConnectionOptions
            {
                DefaultStreamErrorCode = 1,
                DefaultCloseErrorCode = 1,
                HandshakeTimeout = TimeSpan.FromSeconds(60),
                IdleTimeout = TimeSpan.FromMinutes(60),
                ServerAuthenticationOptions = new SslServerAuthenticationOptions
                {
                    ApplicationProtocols = [ClientAlpn, ReceiverAlpn],
                    ServerCertificate = ServerCertificate,
                    ClientCertificateRequired = true,
                    RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true
                }
            };

            return new ValueTask<QuicServerConnectionOptions>(options);
        }

        private static async Task ForwardDataAsync(Stream source, Stream destination, CancellationToken cancellationToken)
        {
            var buffer = new byte[BufferSize];
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var readTask = source.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                    var timeoutTask = Task.Delay(100, cancellationToken);
                    
                    var completedTask = await Task.WhenAny(readTask, timeoutTask).ConfigureAwait(false);
                    
                    if (completedTask == readTask && !cancellationToken.IsCancellationRequested)
                    {
                        int bytesRead = await readTask.ConfigureAwait(false);
                        if (bytesRead == 0)
                        {
                            break;
                        }
                        
                        await destination.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
                        await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
                    }
                }
            }
            catch (TaskCanceledException)
            {
                // Handle task cancellation
            }
            catch (QuicException quicEx)
            {
                Console.WriteLine($"QUIC error during data forwarding: {quicEx.Message}");
                throw;
            }
            catch (IOException ioEx)
            {
                Console.WriteLine($"IO error during data forwarding: {ioEx.Message}");
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Data forwarding error: {ex.Message}");
                throw;
            }
        }
    }
}