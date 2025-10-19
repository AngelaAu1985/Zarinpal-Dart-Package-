interface ZarinpalApi {
    @GET("load_history")
    suspend fun loadHistory(): Response<Map<String, String>>

    @GET("analyze")
    suspend fun analyzeTransactions(): Response<Map<String, Any>>

    @POST("train_model")
    suspend fun trainModel(@Body data: List<Map<String, Any>>): Response<Map<String, Any>>

    @POST("predict")
    suspend fun predictTransaction(
        @Query("amount") amount: Int,
        @Query("currency") currency: String,
        @Query("card_pan") cardPan: String?
    ): Response<Map<String, Float>>

    @GET("retry_suggestions")
    suspend fun getRetrySuggestions(): Response<Map<String, Any>>

    @GET("detect_fraud")
    suspend fun detectFraud(): Response<Map<String, Any>>

    @GET("load_model")
    suspend fun loadModel(): Response<Map<String, String>>
}

fun displayFraudAlerts(fraudCases: List<Map<String, Any>>) {
    fraudCases.forEach { case ->
        Log.d("FraudAlert", "Suspicious transaction: Authority=${case["authority"]}, Amount=${case["amount"]}")
        // Show notification or UI alert
    }
}

fun displayPlot(base64Image: String) {
    val imageBytes = Base64.decode(base64Image, Base64.DEFAULT)
    val bitmap = BitmapFactory.decodeByteArray(imageBytes, 0, imageBytes.size)
    imageView.setImageBitmap(bitmap)
}
