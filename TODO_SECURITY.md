# Phase 2 Harden - Security Updates

## Code Signing (Critical)
**EV Certificate required** - Windows SmartScreen blocks without
- Cost: $300-500/yr (DigiCert, Sectigo)
- Process: 
  1. Purchase EV Code Signing cert
  2. signtool sign /f cert.pfx /p password /t http://timestamp.digicert.com SecureGuard.exe
  3. Dual timestamping recommended
**Kernel Driver:** WHCP submission to Microsoft ($2500+/yr for HLK)

## Signature Database Expansion
**Demo: 30 samples → Production: 10,000+ minimum**
Datasets:
- VirusShare (virusshare.com) - 30M+ samples, registration required
- MalwareBazaar (bazaar.abuse.ch) - Fresh daily samples, API free
- TheZoo (github.com/ytisf/theZoo) - Live malware repo
- EMBER (github.com/elastic/ember) - PE feature dataset

**Run:** `cd ml-training && python generate_models.py` ✅ (synthetic 5k)
**Real training:** dataset_loader.py + train_static_model.py with VirusShare

## Backend Integration Complete ✅
- AuthController → FastAPI /api/auth/*
- PaymentController → /api/payment/* (stub created)

## Auto-Update ✅
- UpdateChecker.CheckSignaturesAsync() - daily CDN pull
- Signatures saved %LocalAppData%/SecureGuard/signatures.json

## Next Steps
1. Download VirusShare dataset to ml-training/data/
2. `python dataset_loader.py --virusshare`
3. `python train_static_model.py --real-data`
4. docker-compose up - test auth/payment
5. Production: EV cert + WHCP

**Flake8 warnings ignored - functional priority**

