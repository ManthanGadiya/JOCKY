FROM alpine:3.19
RUN apk add --no-cache yara python3
WORKDIR /app
COPY yara/rules.yar /app/rules.yar
COPY sigma/rules.yml /app/sigma/rules.yml
COPY testdata/ /app/testdata/
CMD ["sh","-c","echo '[detector] YARA ready' && yara /app/rules.yar /app/testdata/hollowing.json 2>&1 | head -20 && echo 'Risk engine ready' && tail -f /dev/null"]
