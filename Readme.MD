<div align="center">

```
  ▄▄▄   ▄▄·  ▄• ▄▌▄▄▄  ▄▄▌ 
  ▀▄ █·▐█ ▌▪ █▪██▌▀▄ █·██•  
  ▐▀▀▄ ██ ▄▄ █▌▐█▌▐▀▀▄ ██▪  
  ▐█•█▌▐███▌ ▐█▄█▌▐█•█▌▐█▌▐▌
  .▀  ▀·▀▀▀   ▀▀▀ .▀  ▀.▀▀▀ 
```

**curl with a brain — built for bug bounty hunters**

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/aptspyder/acurl?style=flat-square&color=00ff88)](https://github.com/aptspyder/acurl/releases)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

</div>

---

Automatically highlights **JWTs, secrets, API keys, AWS keys, endpoints, CORS issues, cookies, IPs, emails** and more. Supports JS auto-mapping to extract hidden API structure.

## Install

```bash
go install github.com/aptspyder/acurl/v2@latest
```

**Add to PATH:**
```bash
# Linux / Kali / WSL
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc && source ~/.bashrc

# Zsh
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.zshrc && source ~/.zshrc

# Windows PowerShell
$env:PATH += ";$(go env GOPATH)\bin"
```

## Usage

```
acurl [options] <URL>

  -i            Show response headers
  -X METHOD     HTTP method (default: GET)
  -H HEADER     Custom header (repeatable)
  -d DATA       Request body
  -L            Follow redirects
  -k            Skip TLS verify
  -t SECS       Timeout (default: 30)
  --map         Auto-fetch & map all JS files → API tree
  -F            Findings summary only
  --json        Output findings as JSON
  -T N          JS fetch threads (default: 5)
  -o FILE       Save body to file
  -v            Verbose
```

## Examples

```bash
# Basic recon
acurl -i https://api.target.com

# With auth header
acurl -i -H 'Authorization: Bearer TOKEN' https://api.target.com/v1/users

# Map all JS files + extract API structure
acurl -i --map https://target.com

# Findings only as JSON
acurl -F --json https://api.target.com | jq .

# POST request
acurl -i -X POST -d '{"user":"test"}' -H 'Content-Type: application/json' https://api.target.com/login
```

## Detects

`JWT` `AWS_KEY` `PRIVKEY` `SECRET` `TOKEN` `CORS*` `COOKIE` `SERVER` `GRAPHQL` `S3` `ENDPOINT` `EMAIL` `IP`
