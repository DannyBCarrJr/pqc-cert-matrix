FROM eclipse-temurin:21
WORKDIR /app
# Same BC version as the composite mint and the bouncycastle client column, so
# the isolation server and the rest of the matrix agree on one BC release.
ARG BC_VERSION=1.82
ARG BASE=https://repo1.maven.org/maven2/org/bouncycastle
ADD ${BASE}/bcprov-jdk18on/${BC_VERSION}/bcprov-jdk18on-${BC_VERSION}.jar /app/lib/
ADD ${BASE}/bcpkix-jdk18on/${BC_VERSION}/bcpkix-jdk18on-${BC_VERSION}.jar /app/lib/
ADD ${BASE}/bcutil-jdk18on/${BC_VERSION}/bcutil-jdk18on-${BC_VERSION}.jar /app/lib/
ADD ${BASE}/bctls-jdk18on/${BC_VERSION}/bctls-jdk18on-${BC_VERSION}.jar /app/lib/
COPY Server.java /app/
RUN javac -cp "/app/lib/*" -d /app/classes /app/Server.java
ENTRYPOINT ["java", "-cp", "/app/classes:/app/lib/*", "Server"]
