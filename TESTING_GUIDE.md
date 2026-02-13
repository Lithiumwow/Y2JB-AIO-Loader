# BackPork Testing Guide

The server is now running! Here's how to test the BackPork integration:

## Server Status
- ✅ Server running on: http://127.0.0.1:8000
- ✅ Server also accessible on: http://192.168.1.109:8000
- ✅ DNS Server active on port 53

## Testing Steps

### 1. Access the BackPork Page
Open your browser and navigate to:
```
http://127.0.0.1:8000/backpork
```
or
```
http://192.168.1.109:8000/backpork
```

### 2. Set PS5 IP Address
- Go to the main page (http://127.0.0.1:8000) first
- Enter your PS5's IP address in the "PS5 IP Address" field
- Set the FTP Port (default: 1337)

### 3. Test BackPork Features

#### A. Send Payloads
1. Click "Send BackPork & FTP Payloads"
2. This should send:
   - `ftpsrv-ps5.elf` (FTP server)
   - `ps5-backpork.elf` (BackPork payload)
3. Check for success/error messages

#### B. List Games
1. Select your firmware version (6xx or 7xx)
2. Click "Refresh" to scan for installed games
3. Games should appear in the list

#### C. Select a Game
1. Click on a game from the list
2. The fakelib folder should be created automatically
3. Library processing section should appear

#### D. Process Libraries
1. Click "Process & Upload Libraries"
2. This will:
   - Fetch libraries from `/system/common/lib`
   - Apply BPS patches
   - Fake sign the libraries
   - Upload to the game's fakelib folder
3. Check the status messages for each library

## Expected Behavior

### Success Cases
- ✅ Payloads send successfully
- ✅ Games list appears
- ✅ Fakelib folder created
- ✅ Libraries processed (if decrypted ELF files are available)

### Known Limitations
- ⚠️ Libraries from `/system/common/lib` are SELF files (encrypted)
- ⚠️ BPS patches require ELF files (decrypted)
- ⚠️ You may need to decrypt SELF files manually first

## Troubleshooting

### "backpork.elf not found"
- Make sure `ps5-backpork.elf` is in `Y2JB-WebUI/payloads/` folder
- The file should be named `ps5-backpork.elf` or `backpork.elf`

### "Library is in SELF format"
- This is expected - libraries need to be decrypted first
- Use `ps5_elf_sdk_downgrade.py` or similar tool to decrypt
- Place decrypted ELF files in `cache/backpork/` with the same names

### "Patch file not found"
- Verify patches are in `BackPork/patches/6xx/` or `BackPork/patches/7xx/`
- Check that patch file names match library names (e.g., `libSceAgc.bps`)

### "make_fself.py not found"
- Verify `make_fself/make_fself.py` exists in the workspace root
- Check file permissions

## Testing Checklist

- [ ] Server starts without errors
- [ ] BackPork page loads
- [ ] Can send payloads (if PS5 IP is set)
- [ ] Can list games (if FTP is accessible)
- [ ] Can create fakelib folder
- [ ] Can process libraries (if decrypted files available)

## Next Steps

1. **Test with a real PS5:**
   - Set PS5 IP address
   - Send payloads
   - List games
   - Try processing libraries

2. **If libraries are SELF format:**
   - Decrypt them first
   - Then try processing again

3. **Monitor server logs:**
   - Check console output for errors
   - Look for `[BACKPORK]` log messages

## Notes

- The server is running in the background
- To stop the server, press CTRL+C in the terminal
- All temporary files are stored in `cache/backpork/`
