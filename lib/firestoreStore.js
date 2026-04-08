const { Firestore } = require("@google-cloud/firestore");

class UserStateStore {
  constructor() {
    const options = {};
    if (process.env.FIRESTORE_PROJECT_ID) {
      options.projectId = process.env.FIRESTORE_PROJECT_ID;
    }
    if (process.env.FIRESTORE_DATABASE_ID) {
      options.databaseId = process.env.FIRESTORE_DATABASE_ID;
    }
    this.client = new Firestore(options);
  }

  savedCvesRef(userId) {
    return this.client.collection("users").doc(userId).collection("saved_cves");
  }

  watchedProductsRef(userId) {
    return this.client.collection("users").doc(userId).collection("watched_products");
  }

  async getSavedCves(userId) {
    const snapshot = await this.savedCvesRef(userId).get();
    return snapshot.docs.map((doc) => String(doc.id)).sort();
  }

  async addSavedCve(userId, cveId) {
    await this.savedCvesRef(userId).doc(String(cveId)).set({
      cve_id: String(cveId),
      created_at: new Date().toISOString()
    });
  }

  async removeSavedCve(userId, cveId) {
    await this.savedCvesRef(userId).doc(String(cveId)).delete();
  }

  async getWatchedProducts(userId) {
    const snapshot = await this.watchedProductsRef(userId).get();
    return snapshot.docs.map((doc) => ({
      product_id: Number(doc.id),
      ...doc.data()
    })).sort((a, b) => a.product_id - b.product_id);
  }

  async addWatchedProduct(userId, product) {
    const productId = Number(product.product_id);
    await this.watchedProductsRef(userId).doc(String(productId)).set({
      product_id: productId,
      product_name: product.product_name || "",
      vendor_name: product.vendor_name || "",
      created_at: new Date().toISOString()
    });
  }

  async removeWatchedProduct(userId, productId) {
    await this.watchedProductsRef(userId).doc(String(productId)).delete();
  }
}

module.exports = { UserStateStore };
