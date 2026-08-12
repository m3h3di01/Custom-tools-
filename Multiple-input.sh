while read -r url; do
    python3 secretfinder.py -i "$url" -o cli
done < jsfiles.txt | tee secrets.txt
