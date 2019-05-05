**重要事项**: 这个文件是伴随 Firefox 中的策略(policies)一起处于活动开发中的。要获得对应于特定发行版的策略信息，转到 https://github.com/mozilla/policy-templates/releases 。

指定策略在 Windows 上可以使用 __组策略__ 模板 (https://github.com/mozilla/policy-templates/tree/master/windows)，在 macOS 上可以使用 configuration profiles (https://github.com/mozilla/policy-templates/tree/master/mac)，或者通过创建一个名为 `policies.json` 的文件。在 Windows 上，在 EXE 所在的位置中创建一个称为 `distribution` 的目录并把该文件放到那里。 在 Mac 上，该文件转到 `Firefox.app/Contents/Resources/distribution` 中。 在 Linux 上，文件转到 `firefox/distribution` 中，其中 `firefox` 是 Firefox 的安装目录，它随着发行版而有所不同。

JSON 文件的内容应该类似这样:
```
{
  "policies": {
    ...POLICIES...
  }
}
```
策略记录如下。


**注意**: 尽管在这个自述文件中使用了注释以作记录，但是在实际的 JSON 文件中注释是无效的。在尝试部署前应移除所有的注释。

### AppUpdateURL
这个策略是用于更改用于应用程序更新的 URL
```
{
  "AppUpdateURL": "http://yoursite.com"
}
```


### Authentication
这个策略是用于配置支持集成身份验证(integrated authentication)。查看 https://developer.mozilla.org/en-US/docs/Mozilla/Integrated_authentication 获取更多信息。
```
{
  "policies": {
    "Authentication": {
      "SPNEGO": ["mydomain.com", "https://myotherdomain.com"],
      "Delegated": ["mydomain.com", "https://myotherdomain.com"],
      "NTLM": ["mydomain.com", "https://myotherdomain.com"],
      "AllowNonFQDN": {
        "SPNEGO": true,
        "NTLM": true
      }
    }
  }
}
```
### BlockAboutAddons
这个策略移除对 about:addons 的访问权。
```
{
  "policies": {
    "BlockAboutAddons": true
  }
}
```
### BlockAboutConfig
这个策略移除对 about:config 的访问权。
```
{
  "policies": {
    "BlockAboutConfig": true
  }
}
```
### BlockAboutProfiles
这个策略移除对 about:profiles 的访问权。
```
{
  "policies": {
    "BlockAboutProfiles": true
  }
}
```
### BlockAboutSupport
这个策略移除对 about:support 的访问权。
```
{
  "policies": {
    "BlockAboutSupport": true
}
```
### Bookmarks
这个策略让你指定书签。你可以拥有任意数量的书签，尽管在 ADMX 文件中仅指定的十个。
Placement(位置)可以指定为 toolbar (工具栏)或 menu (菜单)。若指定了文件夹，则自动创建它，而且带同一文件夹名称的书签会组合在一起。
```
{
  "policies": {
    "Bookmarks": [
      {
        "Title": "Example",
        "URL": "http://example.org",
        "Favicon": "http://example.com/favicon.ico",
        "Placement": ["toolbar", "menu"],
        "Folder": "FolderName"
      }
    ]
  }
}
```
### Certificates
这个策略可以用于安装证书或者从 Mac 和 Windows 上的系统证书存储中读取证书。

ImportEnterpriseRoots 键将使 Firefox 从系统证书存储中导入。

Install Certificates 键按默认将会在下面列出的位置中搜索。
从 Firefox 65 开始，你可以指定一个包含 UNC 的完全限定路径。(查看示例中的 cert3.der 和 cert4.pem)。

**如果你希望从 UNC 路径中加载证书，那么建议你必须使用双反斜杠。**
示例: \\SERVER\\CERTS\CERT5.PEM


若 Firefox 在你的完全限定路径中找不到东西，它将会搜索默认目录。

证书可以位于下列位置:
- Windows
  - %USERPROFILE%\AppData\Local\Mozilla\Certificates
  - %USERPROFILE%\AppData\Roaming\Mozilla\Certificates
- macOS
  - /Library/Application Support/Mozilla/Certificates
  - ~/Library/Application Support/Mozilla/Certificates
- Linux
  - /usr/lib/mozilla/certificates
  - /usr/lib64/mozilla/certificates
  - ~/.mozilla/certificates


```
{
  "policies": {
    "Certificates": {
      "ImportEnterpriseRoots": true,
      "Install": ["cert1.der", "cert2.pem", "%SYSTEMDRIVE%\Company\cert3.der", "/Library/Company/cert4.pem", "\\server\\certs\\cert.pem"]
    }
  }
}
```
### Cookies
这个策略控制和 Cookies 相关的各种设置。
```
{
  "policies": {
    "Cookies": {
      "Allow": ["http://example.org/"], /* 总是允许 cookies 的域 */
      "Block": ["http://example.edu/"], /* 总是拦截 cookies 的域 */
      "Default": [true|false], /* 这个设定 "Accept cookies from websites" (接受来自网站的 cookies)的默认值 */
      "AcceptThirdParty": ["always", "never", "from-visited"], /* 这个设定 "Accept third-party cookies" (接受第三方 cookies)的默认值 */
      "ExpireAtSessionEnd":  [true|false], /* 这个决定 cookies 过期的时机 */
      "RejectTracker": [true|false], /* 仅拒绝 trackers(跟踪者) */
      "Locked": [true|false] /* 若这个是 true，则 cookies 首选项不能更改 */
    }
  }
}
```
### DNSOverHTTPS
这个策略配置 DNS over HTTPS。
```
{
  "policies": {
    "DNSOverHTTPS": {
      "Enabled": [true|false],
      "ProviderURL": "URL_TO_ALTERNATE_PROVIDER",
      "Locked": [true|false]
    }
  }
}
```
### DisableSetDesktopBackground
这个策略移除右击图像时的"Set As Desktop Background..."(设为桌面背景...)菜单项。
```
{
  "policies": {
    "DisableSetDesktopBackground": true
  }
}
```
### DisableMasterPasswordCreation
若这个策略被设为 true，则移除主密码功能。
```
{
  "policies": {
    "DisableMasterPasswordCreation": [true|false]
  }
}
```
### DisableAppUpdate
这个策略关闭应用程序更新。
```
{
  "policies": {
    "DisableAppUpdate": true
  }
}
```
### DisableBuiltinPDFViewer
这个策略禁用内建的 PDF 查看器。 PDF 文件会被下载并外部发送。
```
{
  "policies": {
    "DisableBuiltinPDFViewer": true
  }
}
```
### DisableDeveloperTools
这个策略移除对所有开发者工具的访问。
```
{
  "policies": {
    "DisableDeveloperTools": true
  }
}
```
### DisableFeedbackCommands
这个策略禁用报告站点(Submit Feedback/提交反馈, Report Deceptive Site/报告欺诈站点)的菜单项。
```
{
  "policies": {
    "DisableFeedbackCommands": true
  }
}
```
### DisableFirefoxScreenshots
这个策略移除对 Firefox 截图的访问。
```
{
  "policies": {
    "DisableFirefoxScreenshots": true
  }
}
```
### DisableFirefoxAccounts
这个策略禁用同步。
```
{
  "policies": {
    "DisableFirefoxAccounts": true
  }
}
```
### DisableFirefoxStudies
这个策略禁用 Firefox studies (Shield)。
```
{
  "policies": {
    "DisableFirefoxStudies": true
  }
}
```
### DisableForgetButton
这个策略禁用 "Forget" (忘记)按钮。
```
{
  "policies": {
    "DisableForgetButton": true
  }
}
```
### DisableFormHistory
这个策略关闭 browser.formfill.enable 首选项。
```
{
  "policies": {
    "DisableFormHistory": true
  }
}
```
### DisablePocket
这个策略关闭 Pocket。
```
{
  "policies": {
    "DisablePocket": true
  }
}
```
### DisablePrivateBrowsing
这个策略移除对隐私浏览的访问。
```
{
  "policies": {
    "DisablePrivateBrowsing": true
  }
}
```
### DisableProfileImport
这个策略禁用在书签窗口中的 "Import data from another browser"(从另一个浏览器中导入数据)的选项。
```
{
  "policies": {
    "DisableProfileImport": true
  }
}
```
### DisableProfileRefresh
这个策略禁用 about:support 和 support.mozilla.org 上的 Refresh Firefox (刷新 Firefox)按钮。
```
{
  "policies": {
    "DisableProfileRefresh": true
  }
}
```
### DisableSafeMode
这个策略仅禁用 Windows 和 macOS 上的安全模式。
```
{
  "policies": {
    "DisableSafeMode": true
  }
}
```
### DisableSecurityBypass
这个策略防止用户在特定情况下绕过安全性设置。
```
{
  "policies": {
    "DisableSecurityBypass": {
      "InvalidCertificate": [true|false], /* 防止在显示无效证书时添加例外 */
      "SafeBrowsing": [true|false]        /* 防止选择"忽略风险"并无论如何都要访问有害站点 */
    }
  }
}
```
### DisableSystemAddonUpdate
这个策略防止系统附加组件被更新或安装。
```
{
  "policies": {
    "DisableSystemAddonUpdate": true
  }
}
```
### DisableTelemetry
这个策略防止遥测数据的上传。

Mozilla 建议你不要禁用遥测。 通过遥测收集的信息有助于我们为类似于你一样的企业构建更好的产品。
```
{
  "policies": {
    "DisableTelemetry": true
  }
}
```
### DisplayBookmarksToolbar
这个策略按默认开启书签工具栏。 用户仍可关闭它，而它将保持关闭状态。
```
{
  "policies": {
    "DisplayBookmarksToolbar": true
  }
}
```
### DisplayMenuBar
这个策略按默认开启菜单栏。 用户仍可关闭它，而它将保持关闭状态。
```
{
  "policies": {
    "DisplayMenuBar": true
  }
}
```
### DontCheckDefaultBrowser
这个策略阻止 Firefox 在启动时检查是否是默认浏览器。
```
{
  "policies": {
    "DontCheckDefaultBrowser": true
  }
}
```
### EnableTrackingProtection
这个策略影响跟踪保护。

若不配置这个策略，则跟踪保护在浏览器中按默认不启用，而在隐私浏览中则按默认启用，并且用户可以更改它。

若 Value 被设为 false，则在普通浏览器和隐私浏览中跟踪保护都被禁用并锁定。

若 Value 被设为 true，则在普通浏览器和隐私浏览中跟踪保护都会按默认被启用。

如果你想防止用户更改它，你可以选择设定 Locked 值。
```
{
  "policies": {
    "EnableTrackingProtection": {
      "Value": [true, false],
      "Locked": [true, false]
    }
}
```
### Extensions
这个策略控制扩展的安装、卸载和锁定。锁定的扩展不能禁用或卸载。
对于 Install，你必须指定 URLs 或路径的列表。
对于 Uninstall 和 Locked，你要指定扩展 IDs。
```
{
  "policies": {
    "Extensions": {
      "Install": ["https://addons.mozilla.org/firefox/downloads/somefile.xpi", "//path/to/xpi"],
      "Uninstall": ["addon_id@mozilla.org"],
      "Locked":  ["addon_id@mozilla.org"]
    }
  }
}
```
### HardwareAcceleration
这个策略通过锁定首选项 layers.acceleration.disabled 为 true 来禁用硬件加速。
```
{
  "policies": {
    "HardwareAcceleration": false
  }
}
```
### NoDefaultBookmarks
这个策略防止默认书签或智能书签(最常访问，近期标记)被创建。 注: 这个策略仅在配置档首次运行前使用时有效。
```
{
  "policies": {
    "NoDefaultBookmarks": true
  }
}
```
### OfferToSaveLogins
这个策略设定 signon.rememberSignons 首选项。 它决定 Firefox 是否提供保存密码功能。它可以被启用或禁用。
```
{
  "policies": {
    "OfferToSaveLogins": true
  }
}
```
### Homepage
这个策略设定默认主页值以及默认开始页面。 它还可以用于锁定主页或添加额外的主页。
```
{
  "policies": {
    "Homepage": {
      "URL": "http://example.com/",
      "Locked": true,
      "Additional": ["http://example.org/",
                     "http://example.edu/"],
      "StartPage": ["none", "homepage", "previous-session"]
    }
  }
}
```
### PopupBlocking
这个策略设定允许弹出窗口的域。 它还设定默认的弹出策略。
```
{
  "policies": {
    "PopupBlocking": {
      "Allow": ["http://example.org/",
                "http://example.edu/"],
      "Default": [true|false], /* 若这个被设为 false，则按默认启用弹出窗口。 */
      "Locked": [true|false]
    }
  }
}
```
### InstallAddonsPermission
这个策略设定可以安装扩展的域，以及默认行为。
```
{
  "policies": {
    "InstallAddonsPermission": {
      "Allow": ["http://example.org/",
                "http://example.edu/"],
      "Default": [true|false] /* 若这个被设为 false，则附加组件不能由用户安装 */
    }
  }
}
```
### FlashPlugin
这个策略设定在指定域上的 Flash 的行为，以及默认行为。
```
{
  "policies": {
    "FlashPlugin": {
      "Allow": ["http://example.org/"], /* 在允许列表上的站点不会改变 Flash 完全被禁用 */
      "Block": ["http://example.edu/"],
      "Default": [true|false], /* 若这个被设为 true，则 Flash 总是被启用。 若它被设为 false，则 Flash 永不被启用 */
      "Locked": [true|false]
    }
  }
}
```
### OverrideFirstRunPage
这个策略允许你改变首次运行页面。 如果你留空 URL，将不会显示首次运行页面。
```
{
  "policies": {
    "OverrideFirstRunPage": "http://example.org"
  }
}
```
### OverridePostUpdatePage
这个策略允许你改写升级页面。 如果你留空该 URL，将不会显示升级页面。
```
{
  "policies": {
    "OverridePostUpdatePage": "http://example.org"
  }
}
```
### Permissions
这个策略允许你更改和摄像头、麦克风、定位以及通知有关的权限
```
{
  "policies": {
    "Permissions": {
      "Camera": {
        "Allow": ["http://example.org/"], /* 按默认允许摄像头访问的原点 */
        "Block": ["http://example.org/"], /* 按默认阻止摄像头访问的原点 */
        "BlockNewRequests": [true|false], /* 阻止访问摄像头的新请求 */
        "Locked": [true|false] /* 不允许用户更改摄像头首选项 */
      },
      "Microphone": {
        "Allow": ["http://example.org/"], /* 按默认允许麦克风访问的原点 */
        "Block": ["http://example.org/"], /* 按默认阻止麦克风访问的原点 */
        "BlockNewRequests": [true|false], /* 阻止访问麦克风的新请求 */
        "Locked": [true|false] /* 不允许用户更改麦克风首选项 */
      },
      "Location": {
        "Allow": ["http://example.org/"], /* 按默认允许定位访问的原点 */
        "Block": ["http://example.org/"], /* 按默认阻止定位访问的原点 */
        "BlockNewRequests": [true|false], /* 阻止访问定位的新请求 */
        "Locked": [true|false] /* 不允许用户更改定位首选项 */
      },
      "Notifications": {
        "Allow": ["http://example.org/"], /* 按默认允许发送通知的原点 */
        "Block": ["http://example.org/"], /* 按默认阻止发送通知的原点 */
        "BlockNewRequests": [true|false], /* 阻止发送通知的新请求 */
        "Locked": [true|false] /* 不允许用户更改通知首选项 */
      }
    }
  }
}
```
### Proxy
这个策略允许你指定代理设置。这些设置对应于 Firefox 首选项中的连接设置。
要指定端口，使用冒号(:)附加它们到主机名后。若 Locked 被设为 true，则该值不能由用户更改。
```
{
  "policies": {
    "Proxy": {
      "Mode": ["none", "system", "manual", "autoDetect", "autoConfig"],
      "Locked": [true, false],
      "HTTPProxy": "hostname",
      "UseHTTPProxyForAllProtocols": [true, false],
      "SSLProxy": "hostname",
      "FTPProxy": "hostname",
      "SOCKSProxy": "hostname",
      "SOCKSVersion": [4, 5],
      "Passthrough": "直通地址/域名的列表",
      "AutoConfigURL": "URL_TO_AUTOCONFIG",
      "AutoLogin":  [true, false],
      "UseProxyForDNS": [true, false]
    }
  }
}
```
### RequestedLocales
这个策略按优先顺序设定用于应用程序的请求区域设置的列表。 它将是相应的语言包变成活动。
```
{
  "policies": {
    "RequestedLocales": ["de", "en-US"]
  }
}
```
### SanitizeOnShutdown
若这个策略被设为 true，则关闭 Firefox 时所有数据被清除。 这个包括浏览和下载历史、Cookies、活动登录、缓存、表单和搜索历史、站点首选项和脱机网站数据。
```
{
  "policies": {
    "SanitizeOnShutdown": [true|false]
  }
}
```
### SearchBar
这个策略可以用于决定搜索栏是独立的还是和 URL 栏组合在一起。
```
{
  "policies": {
    "SearchBar": ["unified", "separate"]
  }
}
```
### WebsiteFilter
这个策略阻止网站被访问。 参数需要一个匹配式样(Match Patterns)数组，如 https://developer.mozilla.org/en-US/Add-ons/WebExtensions/Match_patterns 中所记录。目前仅支持 http/https 地址。 数组被限制为每个1000条。
```
{
  "policies": {
    "WebsiteFilter": {
      "Block": ["<all_urls>"],
      "Exceptions": ["http://example.org/*"]
    }
  }
}
```
### Search Engines (这个策略仅在 ESR 版本上有效。)
这个策略允许你添加新的搜索引擎，移除或隐藏搜索引擎，以及设定默认项并防止从网页安装搜索引擎。仅需要 Name 和 URLTemplate。
```
{
  "policies": {
    "SearchEngines": {
      "Add": [
        {
          "Name": "",
          "URLTemplate": "包含 {searchTerms} 来代表搜索术语的 URL",
          "Method": ["GET", "POST"],
          "IconURL": "图标的 URL",
          "Alias": "可以用于访问引擎的别名",
          "Description": "说明",
          "SuggestURLTemplate": "使用 {searchTerms} 的建议的 URL"
        }
      ],
      "Default": "引擎的名称",
      "PreventInstalls": [true|false],
      "Remove": ["Twitter", "Wikipedia (en)"]
    }
  }
}
```
### SecurityDevices
这个策略允许你添加 PKCS #11 模块
```
{
  "policies": {
    "SecurityDevices": {
      "NAME_OF_DEVICE": "PATH_TO_LIBRARY_FOR_DEVICE"
    }
  }
}
```
### SSLVersionMin
这个策略允许你设定最小 TLS 版本。
```
{
  "policies": {
    "SSSLVersionMin": ["tls1", "tls1.1", "tls1.2",. "tls1.3"]
  }
}

```
### SSLVersionMax
这个策略允许你设定最大 TLS 版本。
```
{
  "policies": {
    "SSSLVersionMax": ["tls1", "tls1.1", "tls1.2",. "tls1.3"]
  }
}
```
