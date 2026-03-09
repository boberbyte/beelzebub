#!/bin/bash
APIKEY="${VT_APIKEY}"
COLLECTION_ID="be3674666b18993e444819ea3e3b049b2bfdc50c4587a8cf2fc89e65a1317ea1"
UPLOADED_LOG="/home/azureuser/hephaestus/vt_uploaded.txt"

if [ -z "$APIKEY" ]; then
  echo "ERROR: VT_APIKEY inte satt"
  exit 1
fi

touch "$UPLOADED_LOG"

# Sätt läsrättigheter på samples (sparas som root av Docker)
sudo chmod 644 * 2>/dev/null || true

for f in *; do
  [ -f "$f" ] || continue

  hash=$(sha256sum "$f" | cut -d' ' -f1)

  if grep -qF "$hash" "$UPLOADED_LOG"; then
    echo "$f: redan uppladdad, hoppar över"
    continue
  fi

  echo -n "$f ($hash): "

  # Ladda upp fil
  result=$(curl -s \
    --request POST \
    --url https://www.virustotal.com/api/v3/files \
    --header "x-apikey: $APIKEY" \
    --form file=@"$f")

  code=$(echo "$result" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('error',{}).get('code','ok'))" 2>/dev/null)

  sleep 15  # 1 lookup gjord — vänta innan nästa

  if [ "$code" = "ConflictError" ] || [ "$code" = "ok" ]; then
    # Lägg till i collection
    curl -s \
      --request POST \
      --url "https://www.virustotal.com/api/v3/collections/$COLLECTION_ID/relationships/files" \
      --header "x-apikey: $APIKEY" \
      --header "Content-Type: application/json" \
      --data "{\"data\":[{\"type\":\"file\",\"id\":\"$hash\"}]}" > /dev/null
    echo "$hash" >> "$UPLOADED_LOG"
    echo "tillagd i collection"
  else
    echo "FEL: $result"
  fi

  sleep 15  # 2 lookups gjorda — vänta innan nästa fil
done
