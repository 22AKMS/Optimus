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
    return snapshot.docs.map((doc) => {
      const data = doc.data() || {};
      return {
        product_id: Number(doc.id),
        ...data,
        created_at: data.created_at || null,
        last_viewed_at: data.last_viewed_at || data.created_at || null
      };
    }).sort((a, b) => {
      const vendorCompare = String(a.vendor_name || "").localeCompare(String(b.vendor_name || ""));
      if (vendorCompare !== 0) return vendorCompare;
      const productCompare = String(a.product_name || "").localeCompare(String(b.product_name || ""));
      if (productCompare !== 0) return productCompare;
      return a.product_id - b.product_id;
    });
  }

  async addWatchedProduct(userId, product) {
    const productId = Number(product.product_id);
    const ref = this.watchedProductsRef(userId).doc(String(productId));
    const snapshot = await ref.get();
    const existing = snapshot.exists ? snapshot.data() || {} : {};
    const now = new Date().toISOString();

    await ref.set({
      product_id: productId,
      product_name: product.product_name || "",
      vendor_name: product.vendor_name || "",
      created_at: existing.created_at || now,
      last_viewed_at: existing.last_viewed_at || existing.created_at || now
    });
  }

  async removeWatchedProduct(userId, productId) {
    await this.watchedProductsRef(userId).doc(String(productId)).delete();
  }

  async markWatchedProductsViewed(userId, productIds) {
    const ids = [...new Set((productIds || []).map((value) => Number(value)).filter((value) => value > 0))];
    if (!ids.length) return;

    const viewedAt = new Date().toISOString();
    const batch = this.client.batch();

    ids.forEach((productId) => {
      const ref = this.watchedProductsRef(userId).doc(String(productId));
      batch.set(ref, { last_viewed_at: viewedAt }, { merge: true });
    });

    await batch.commit();
  }
}

module.exports = { UserStateStore };
