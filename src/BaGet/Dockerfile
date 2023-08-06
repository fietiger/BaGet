#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 1290

#FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
#WORKDIR /src
#COPY ["nuget.config", "."]
#COPY ["src/BaGet/BaGet.csproj", "src/BaGet/"]
#COPY ["src/BaGet.Core/BaGet.Core.csproj", "src/BaGet.Core/"]
#COPY ["src/BaGet.Protocol/BaGet.Protocol.csproj", "src/BaGet.Protocol/"]
#COPY ["src/BaGet.Database.Sqlite/BaGet.Database.Sqlite.csproj", "src/BaGet.Database.Sqlite/"]
#COPY ["src/BaGet.Web/BaGet.Web.csproj", "src/BaGet.Web/"]
#RUN dotnet restore "src/BaGet/BaGet.csproj"
COPY . .
#WORKDIR "/src/src/BaGet"
#RUN dotnet build "BaGet.csproj" -c Release -o /app/build

#FROM build AS publish
#RUN dotnet publish "BaGet.csproj" -c Release -o /app/publish /p:UseAppHost=false

#FROM base AS final
#WORKDIR /app
#COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "BaGet.dll"]
