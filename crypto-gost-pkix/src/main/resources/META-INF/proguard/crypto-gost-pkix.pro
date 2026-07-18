# Android: java.net.http отсутствует в Android SDK.
# JdkHttpTspTransport не должен загружаться на Android. Если потребитель
# не ссылается на этот класс, R8 вырежет его на shrink.
-dontwarn java.net.http.**
-dontnote java.net.http.**
