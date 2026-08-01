FROM eclipse-temurin:21
WORKDIR /app
# Pinned to the same BC version that mints the composite certificates, so the
# column tests the minting family's own verifier.
ARG BC_VERSION=1.82
ARG BASE=https://repo1.maven.org/maven2/org/bouncycastle
ADD ${BASE}/bcprov-jdk18on/${BC_VERSION}/bcprov-jdk18on-${BC_VERSION}.jar /app/lib/
ADD ${BASE}/bcpkix-jdk18on/${BC_VERSION}/bcpkix-jdk18on-${BC_VERSION}.jar /app/lib/
ADD ${BASE}/bcutil-jdk18on/${BC_VERSION}/bcutil-jdk18on-${BC_VERSION}.jar /app/lib/
COPY Client.java /app/
RUN javac -cp "/app/lib/*" -d /app/classes /app/Client.java
