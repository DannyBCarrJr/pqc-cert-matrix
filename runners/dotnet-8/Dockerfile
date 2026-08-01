FROM mcr.microsoft.com/dotnet/sdk:8.0
WORKDIR /src
COPY Client.csproj .
COPY Client.cs .
RUN dotnet publish -c Release -o /app
WORKDIR /app
