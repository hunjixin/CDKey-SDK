# CDKey-SDK

a tool for generating and verify CDKey-SDK


# Usage

## Step1:
  generate private key:
```go
priv, err := GeneratePrivKey()
```

## Step2:
  generate key:
```go
cdkey, err := GenerateCDKey(priv, id)
```

# How to Verify

```go
success, vId, err := VerifyCDKey(priv, cdkey)
```