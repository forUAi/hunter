plugins {
  id("com.android.application")
  kotlin("android")
}
android {
  namespace = "example.mobile"
  compileSdk = 35
  defaultConfig { minSdk = 28 }
}
