using System.Runtime.Versioning;
using Xunit;

namespace TokenTrackerWin;

[SupportedOSPlatform("windows")]
public sealed class OAuthLoginWindowTests
{
    [Theory]
    [InlineData(
        "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --single-argument %1",
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe")]
    [InlineData(
        "\"C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -osint -url \"%1\"",
        "C:\\Program Files\\Mozilla Firefox\\firefox.exe")]
    [InlineData(
        "\"C:\\Apps\\BraveSoftware\\Brave-Browser\\Application\\brave.exe\"",
        "C:\\Apps\\BraveSoftware\\Brave-Browser\\Application\\brave.exe")]
    [InlineData(
        "C:\\Tools\\mybrowser.exe \"%1\"",
        "C:\\Tools\\mybrowser.exe")]
    public void ExtractsExecutableFromShellOpenCommand(string openCommand, string expected)
    {
        Assert.Equal(expected, OAuthLoginWindow.ExtractExecutablePath(openCommand));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\"")]
    [InlineData("\" \"")]
    public void UnusableOpenCommandsYieldNoExecutable(string openCommand)
    {
        Assert.Null(OAuthLoginWindow.ExtractExecutablePath(openCommand));
    }

    [Fact]
    public void LaunchSpecUsesNewWindowFlagAndQuotedUrl()
    {
        var url = "https://example.com/authorize?client_id=abc&redirect_uri=tokentracker%3a%2f%2fauth%2fcallback";
        // The whitelist matches on the executable NAME, so the fixture must be
        // exactly "msedge.exe" — a unique temp directory keeps it collision-free.
        var dir = Path.Combine(Path.GetTempPath(), $"tokentracker-tests-{Guid.NewGuid():N}");
        var exePath = Path.Combine(dir, "msedge.exe");
        try
        {
            Directory.CreateDirectory(dir);
            File.WriteAllText(exePath, "");
            var command = $"\"{exePath}\" --single-argument %1";

            var launch = OAuthLoginWindow.ResolveDefaultBrowserLaunch(url, command);

            Assert.NotNull(launch);
            Assert.Equal(exePath, launch.Value.ExePath);
            Assert.Equal("msedge", launch.Value.ProcessName);
            Assert.Equal($"--new-window \"{url}\"", launch.Value.Arguments);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best-effort temp cleanup */ }
        }
    }

    [Fact]
    public void HandlersOutsideTheKnownBrowserListFallBackToShell()
    {
        // cmd.exe exists on every Windows box but is not a browser: the direct
        // --new-window launch must be declined so Launch opens the URL through
        // the shell instead (unknown handlers keep their own argument
        // conventions and may not open anything when launched directly).
        var systemExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        Assert.NotNull(systemExe);

        Assert.Null(OAuthLoginWindow.ResolveDefaultBrowserLaunch(
            "https://example.com/authorize",
            $"\"{systemExe}\" --single-argument %1"));
    }

    [Fact]
    public void MissingExecutableFileYieldsNoLaunchSpec()
    {
        var launch = OAuthLoginWindow.ResolveDefaultBrowserLaunch(
            "https://example.com/authorize",
            "\"C:\\definitely\\not\\installed\\msedge.exe\" --single-argument %1");

        Assert.Null(launch);
    }
}
