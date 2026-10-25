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
        var systemExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        var url = "https://example.com/authorize?client_id=abc&redirect_uri=tokentracker%3a%2f%2fauth%2fcallback";
        var command = $"\"{systemExe}\" --single-argument %1";

        var launch = OAuthLoginWindow.ResolveDefaultBrowserLaunch(url, command);

        Assert.NotNull(launch);
        Assert.Equal(systemExe, launch.Value.ExePath);
        Assert.Equal("cmd", launch.Value.ProcessName);
        Assert.Equal($"--new-window \"{url}\"", launch.Value.Arguments);
    }

    [Fact]
    public void MissingExecutableFileYieldsNoLaunchSpec()
    {
        var launch = OAuthLoginWindow.ResolveDefaultBrowserLaunch(
            "https://example.com/authorize",
            "\"C:\\definitely\\not\\installed\\browser.exe\" --single-argument %1");

        Assert.Null(launch);
    }
}
