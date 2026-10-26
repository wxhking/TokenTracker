using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;

namespace TokenTrackerWin;

[SupportedOSPlatform("windows")]

/// <summary>
/// Opens the OAuth authorize URL in a dedicated window of the default browser
/// (its normal profile, so saved GitHub/Google sessions still apply) and closes
/// that window once the <c>tokentracker://</c> deep link arrives.
///
/// Replaces the previous BrowserTabCloser keyboard sweep, which could never
/// succeed: the provider's redirect chain 302s straight to the
/// <c>tokentracker://</c> custom scheme, so no tab ever sits on the local
/// /auth/callback URL the sweep matched against (windows-host.log showed 13/13
/// "auth callback tab not found", zero closes). Sweeping also stole foreground
/// focus for seconds and overwrote the clipboard on every sign-in.
///
/// Cleanup here is ownership-based, not URL-based: the window is opened by this
/// app, identified as the default browser's new top-level window right after
/// launch, and dismissed with WM_CLOSE — no focus change, no clipboard access.
/// Browsers forward a <c>--new-window</c> launch to an already-running
/// instance, so the window cannot be tracked through the launched Process
/// object; it is found by diffing visible top-level windows of the browser's
/// process name before and after the launch. If the window cannot be
/// identified (unknown default browser, <c>--new-window</c> unsupported), the
/// URL still opens through the shell and cleanup is skipped — the fallback is
/// the old behavior minus the sweep.
/// </summary>
internal sealed class OAuthLoginWindow
{
    // Chromium-family top-level windows (Chrome/Edge/Brave/Opera/Vivaldi share
    // one window class); Firefox uses its own.
    private const string ChromiumWindowClass = "Chrome_WidgetWin_1";
    private const string FirefoxWindowClass = "MozillaWindowClass";

    private const int DiscoverAttempts = 32;
    private const int DiscoverIntervalMs = 250;

    private const uint WM_CLOSE = 0x0010;

    private readonly object _gate = new();
    private nint _trackedWindow;
    private uint _trackedProcessId;
    private string _trackedWindowClass = "";
    private bool _closeWhenFound;
    private int _generation;

    /// <summary>
    /// Opens <paramref name="url"/> in a new window of the default browser and
    /// starts identifying that window. A close requested before identification
    /// finishes is delivered as soon as the window is found.
    /// </summary>
    public void Launch(string url, string logCategory = "browser")
    {
        CloseTracked("superseded by a new sign-in", logCategory);

        // Retire any still-pending discovery from the previous flow BEFORE
        // resolving the browser or falling back to the shell. Without this
        // bump, a launch that ends in the shell fallback leaves the earlier
        // discovery task live — with a close possibly queued by the
        // CloseTracked above — and it would go on to identify and close
        // whatever window the fallback opens instead.
        int generation;
        lock (_gate)
        {
            generation = ++_generation;
            _closeWhenFound = false;
        }

        var command = ReadOpenCommand();
        var launch = command is null ? null : ResolveDefaultBrowserLaunch(url, command);
        if (launch is null)
        {
            Diag.Log(logCategory, "default browser executable not resolved; opening via shell, window cleanup disabled");
            OpenViaShell(url);
            return;
        }

        var knownWindows = SnapshotBrowserWindows(launch.Value.ProcessName);
        try
        {
            using var _ = Process.Start(new ProcessStartInfo(launch.Value.ExePath, launch.Value.Arguments)
            {
                UseShellExecute = false,
            });
        }
        catch (Exception ex)
        {
            Diag.Log(logCategory, $"browser launch failed: {ex.GetType().Name}; falling back to shell");
            OpenViaShell(url);
            return;
        }

        Diag.Log(logCategory, $"oauth login window launched process={launch.Value.ProcessName}");
        _ = Task.Run(() => TrackNewWindow(knownWindows, launch.Value.ProcessName, generation, logCategory));
    }

    /// <summary>
    /// Closes the tracked login window asynchronously (WM_CLOSE, no focus
    /// change). Safe to call repeatedly and safe to call before the window has
    /// been identified.
    /// </summary>
    public void CloseTracked(string reason, string logCategory = "browser")
    {
        nint hwnd;
        uint processId;
        string windowClass;
        lock (_gate)
        {
            if (_trackedWindow != 0)
            {
                (hwnd, processId, windowClass) = (_trackedWindow, _trackedProcessId, _trackedWindowClass);
                _trackedWindow = 0;
                _trackedProcessId = 0;
                _trackedWindowClass = "";
                _closeWhenFound = false;
            }
            else
            {
                // Identification still in flight; deliver the close on find.
                _closeWhenFound = true;
                return;
            }
        }

        PostCloseIfIdentityHolds(hwnd, processId, windowClass, reason, logCategory);
    }

    private void TrackNewWindow(HashSet<nint> knownWindows, string processName, int generation, string logCategory)
    {
        for (var attempt = 0; attempt < DiscoverAttempts; attempt++)
        {
            Thread.Sleep(DiscoverIntervalMs);
            lock (_gate)
            {
                if (_generation != generation) return; // superseded by a newer Launch
            }

            var hwnd = FindNewBrowserWindow(knownWindows, processName);
            if (hwnd == 0) continue;

            GetWindowThreadProcessId(hwnd, out var processId);
            var windowClass = GetWindowClassName(hwnd);

            bool closeNow;
            lock (_gate)
            {
                if (_generation != generation) return;
                _trackedWindow = hwnd;
                _trackedProcessId = processId;
                _trackedWindowClass = windowClass;
                closeNow = _closeWhenFound;
                _closeWhenFound = false;
            }

            if (closeNow)
            {
                PostCloseIfIdentityHolds(hwnd, processId, windowClass,
                    "auth callback arrived before the window was identified", logCategory);
            }
            else
            {
                Diag.Log(logCategory, "OAuth login window identified");
            }
            return;
        }

        Diag.Log(logCategory, "OAuth login window not identified; cleanup skipped");
    }

    /// <summary>HWNDs are recycled once a window is destroyed; only post the
    /// close when the window still belongs to the process and window class
    /// captured at identification time, so an unrelated window that happened
    /// to reuse the HWND is never closed.</summary>
    private void PostCloseIfIdentityHolds(nint hwnd, uint processId, string windowClass, string reason, string logCategory)
    {
        if (IsWindow(hwnd)
            && GetWindowThreadProcessId(hwnd, out var currentPid) != 0
            && currentPid == processId
            && GetWindowClassName(hwnd) == windowClass)
        {
            PostMessage(hwnd, WM_CLOSE, 0, 0);
            Diag.Log(logCategory, $"closed OAuth login window ({reason})");
        }
        else
        {
            Diag.Log(logCategory, $"OAuth login window gone or reused; close skipped ({reason})");
        }
    }

    // Only browsers known to accept `--new-window` are launched directly.
    // Other registered handlers keep their own argument conventions (Firefox
    // registers `-osint -url`, arbitrary apps anything at all), so a direct
    // launch could appear to succeed while opening nothing — those handlers
    // get the plain shell open instead, with cleanup disabled.
    private static readonly HashSet<string> KnownBrowserProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "msedge", "brave", "firefox", "opera", "vivaldi",
    };

    internal static LaunchSpec? ResolveDefaultBrowserLaunch(string url, string openCommand)
    {
        var exePath = ExtractExecutablePath(openCommand);
        if (exePath is null || !File.Exists(exePath)) return null;
        var processName = Path.GetFileNameWithoutExtension(exePath);
        if (!KnownBrowserProcessNames.Contains(processName)) return null;
        return new LaunchSpec(processName, exePath, $"--new-window \"{url}\"");
    }

    /// <summary>Pulls the executable out of a ProgId <c>shell\open\command</c>
    /// template, e.g. <c>"C:\...\msedge.exe" --single-argument %1</c>.</summary>
    internal static string? ExtractExecutablePath(string? openCommand)
    {
        if (string.IsNullOrWhiteSpace(openCommand)) return null;
        var trimmed = openCommand.TrimStart();
        string? exePath;
        if (trimmed.StartsWith('"'))
        {
            var end = trimmed.IndexOf('"', 1);
            exePath = end > 1 ? trimmed[1..end] : null;
        }
        else
        {
            var space = trimmed.IndexOf(' ');
            exePath = space > 0 ? trimmed[..space] : trimmed;
        }
        return string.IsNullOrWhiteSpace(exePath) ? null : exePath;
    }

    private static string? ReadOpenCommand()
    {
        try
        {
            using var choice = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice");
            var progId = choice?.GetValue("ProgId") as string;
            if (string.IsNullOrWhiteSpace(progId)) return null;
            using var command = Registry.ClassesRoot.OpenSubKey($@"{progId}\shell\open\command");
            return command?.GetValue(null) as string;
        }
        catch
        {
            return null;
        }
    }

    private static HashSet<nint> SnapshotBrowserWindows(string processName)
    {
        var pids = ProcessIdsOf(processName);
        var windows = new HashSet<nint>();
        if (pids.Count == 0) return windows;

        EnumWindows((hwnd, _) =>
        {
            if (IsBrowserTopLevelWindow(hwnd, pids)) windows.Add(hwnd);
            return true;
        }, 0);
        return windows;
    }

    private static nint FindNewBrowserWindow(HashSet<nint> knownWindows, string processName)
    {
        var pids = ProcessIdsOf(processName);
        if (pids.Count == 0) return 0;

        nint found = 0;
        EnumWindows((hwnd, _) =>
        {
            if (knownWindows.Contains(hwnd) || !IsBrowserTopLevelWindow(hwnd, pids)) return true;
            found = hwnd;
            return false;
        }, 0);
        return found;
    }

    private static bool IsBrowserTopLevelWindow(nint hwnd, HashSet<int> pids)
    {
        if (!IsWindowVisible(hwnd)) return false;
        if (GetWindowThreadProcessId(hwnd, out var pid) == 0 || !pids.Contains((int)pid)) return false;
        var className = GetWindowClassName(hwnd);
        return className is ChromiumWindowClass or FirefoxWindowClass;
    }

    private static HashSet<int> ProcessIdsOf(string processName)
    {
        var pids = new HashSet<int>();
        foreach (var process in Process.GetProcessesByName(processName))
        {
            using (process) pids.Add(process.Id);
        }
        return pids;
    }

    private static void OpenViaShell(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch { /* no default browser / malformed url */ }
    }

    private static string GetWindowClassName(nint hwnd)
    {
        var buffer = new StringBuilder(256);
        return GetClassName(hwnd, buffer, buffer.Capacity) > 0 ? buffer.ToString() : "";
    }

    private delegate bool EnumWindowsProc(nint hWnd, nint lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc callback, nint lParam);

    [DllImport("user32.dll")]
    private static extern bool IsWindow(nint hWnd);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(nint hWnd);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(nint hWnd, out uint processId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(nint hWnd, StringBuilder buffer, int maxCount);

    [DllImport("user32.dll")]
    private static extern bool PostMessage(nint hWnd, uint msg, nint wParam, nint lParam);
}

internal readonly record struct LaunchSpec(string ProcessName, string ExePath, string Arguments);
