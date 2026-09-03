# Benchmark Computers PowerShell Tools

BMC Tools is a collection of PowerShell scrips to help automate common tasks

<img width="554" height="343" alt="image" src="https://github.com/user-attachments/assets/fea50292-4366-45ef-845d-2c380bd6b232" />

## Usage

In an elevated PowerShell window, run the following command
```powershell
iwr tools.bmcaz.link | iex
```

## Installation (nginx)

Add the following to the vhost file

```nginx
  index index.html;
  
  location / {
    if ($http_user_agent ~* "PowerShell") {
      # Rewrite the request internally to serve the script instead
      rewrite ^/$ /index.ps1 last;
    }

    # Normal browser traffic falls through to serve index.html
    try_files $uri $uri/ =404;
  }
  
  location ~ \.ps1 {
    default_type text/plain;
    charset utf-8;
    add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0";
  }
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)
