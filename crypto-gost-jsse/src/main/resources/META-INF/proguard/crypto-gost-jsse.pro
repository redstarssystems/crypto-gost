# Android: java.net.http отсутствует в Android SDK.
# JdkHttpOcspFetcher и JdkHttpCrlFetcher не должны загружаться на Android.
# Если потребитель не ссылается на эти классы, R8 вырежет их на shrink.
-dontwarn java.net.http.**
-dontnote java.net.http.**
