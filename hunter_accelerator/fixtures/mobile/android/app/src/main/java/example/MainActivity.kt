package example

class MainActivity {
  fun storeRefreshToken(refreshToken: String) {
    encryptedPreferences.edit().putString("refresh_token", refreshToken).apply()
  }
}
