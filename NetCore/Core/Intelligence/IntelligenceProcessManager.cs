using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Core.Intelligence;

/// <summary>
/// Manages the lifecycle of the Python intelligence FastAPI service.
/// Starts the process, waits for it to become healthy, and stops it on dispose.
/// </summary>
public sealed class IntelligenceProcessManager : IDisposable
{
    private readonly string _host;
    private readonly int _port;
    private readonly string _pythonExe;
    private readonly string _workingDirectory;
    private readonly TimeSpan _startupTimeout;
    private readonly HttpClient _healthHttp;
    private Process? _process;
    private bool _disposed;

    public IntelligenceProcessManager(
        string? host = null,
        int? port = null,
        string? pythonExe = null,
        string? workingDirectory = null,
        TimeSpan? startupTimeout = null)
    {
        _host = host
                ?? Environment.GetEnvironmentVariable("INTEL_HOST")
                ?? "0.0.0.0";
        _port = port
                ?? ParseInt(Environment.GetEnvironmentVariable("INTEL_PORT"), 8080);
        _pythonExe = pythonExe ?? "python";
        _workingDirectory = workingDirectory ?? FindProjectRoot();
        _startupTimeout = startupTimeout ?? TimeSpan.FromSeconds(60);
        _healthHttp = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
    }

    public string BaseUrl => $"http://127.0.0.1:{_port}";
    public bool IsRunning => _process is { HasExited: false };

    /// <summary>
    /// Checks whether the intelligence service is already reachable.
    /// Does NOT take a cancellation token — uses only the HttpClient's own timeout
    /// to avoid interference from the startup timeout CTS.
    /// </summary>
    public async Task<bool> IsHealthyAsync()
    {
        try
        {
            var resp = await _healthHttp.GetAsync($"{BaseUrl}/health").ConfigureAwait(false);
            return resp.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Starts the Python intelligence service if it is not already running.
    /// Blocks until the /health endpoint responds or the timeout expires.
    /// </summary>
    public async Task StartAsync(CancellationToken ct = default)
    {
        // If already reachable (user started it manually or previous run), skip.
        if (await IsHealthyAsync().ConfigureAwait(false))
        {
            Console.WriteLine($"[Intelligence] Service already running at {BaseUrl}");
            return;
        }

        Console.WriteLine($"[Intelligence] Starting Python service at {BaseUrl} ...");
        Console.WriteLine($"[Intelligence] Working directory: {_workingDirectory}");

        var psi = new ProcessStartInfo
        {
            FileName = _pythonExe,
            Arguments = "-m intelligence",
            WorkingDirectory = _workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        // Ensure the child process uses the right host/port
        psi.Environment["INTEL_HOST"] = _host;
        psi.Environment["INTEL_PORT"] = _port.ToString();

        _process = Process.Start(psi);
        if (_process is null)
            throw new InvalidOperationException("Failed to start the intelligence process.");

        _process.OutputDataReceived += (_, e) =>
        {
            if (!string.IsNullOrWhiteSpace(e.Data))
                Console.WriteLine($"[Intelligence] {e.Data}");
        };
        _process.ErrorDataReceived += (_, e) =>
        {
            if (!string.IsNullOrWhiteSpace(e.Data))
                Console.WriteLine($"[Intelligence] {e.Data}");
        };
        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();

        // Poll /health until ready
        var deadline = DateTime.UtcNow + _startupTimeout;

        while (DateTime.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();

            if (_process.HasExited)
                throw new InvalidOperationException(
                    $"Intelligence process exited with code {_process.ExitCode} before becoming healthy.");

            if (await IsHealthyAsync().ConfigureAwait(false))
            {
                Console.WriteLine($"[Intelligence] Service is healthy at {BaseUrl}");
                return;
            }

            await Task.Delay(1000, ct).ConfigureAwait(false);
        }

        // One final check
        if (await IsHealthyAsync().ConfigureAwait(false))
        {
            Console.WriteLine($"[Intelligence] Service is healthy at {BaseUrl}");
            return;
        }

        Stop();
        throw new TimeoutException(
            $"Intelligence service did not become healthy within {_startupTimeout.TotalSeconds}s.");
    }

    /// <summary>
    /// Stops the Python intelligence service if we started it.
    /// </summary>
    public void Stop()
    {
        if (_process is null || _process.HasExited)
            return;

        Console.WriteLine("[Intelligence] Stopping Python service ...");
        try
        {
            _process.Kill(entireProcessTree: true);
            _process.WaitForExit(5000);
        }
        catch
        {
            // Best-effort cleanup.
        }
        finally
        {
            _process.Dispose();
            _process = null;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
        _healthHttp.Dispose();
    }

    private static string FindProjectRoot()
    {
        // Walk up from current dir looking for the Python intelligence package
        // (identified by intelligence/__main__.py, not just a folder named intelligence/)
        var dir = Directory.GetCurrentDirectory();
        for (var i = 0; i < 10; i++)
        {
            if (File.Exists(Path.Combine(dir, "intelligence", "__main__.py")))
                return dir;

            var parent = Directory.GetParent(dir);
            if (parent is null) break;
            dir = parent.FullName;
        }

        return Directory.GetCurrentDirectory();
    }

    private static int ParseInt(string? value, int fallback)
        => int.TryParse(value, out var parsed) ? parsed : fallback;
}
