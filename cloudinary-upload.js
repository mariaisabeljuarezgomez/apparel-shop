const cloudinary = require('cloudinary').v2;
// Note: dotenv is loaded in server.js before this module is required

// Configure Cloudinary - Support both individual credentials and CLOUDINARY_URL
if (process.env.CLOUDINARY_URL) {
  // Use the combined URL format
  cloudinary.config({
    url: process.env.CLOUDINARY_URL
  });
} else {
  // Use individual credentials
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
  });
}

/**
 * Upload a base64 image to Cloudinary
 * @param {string} base64Image - Base64 encoded image data
 * @param {string} productName - Name of the product for folder organization
 * @param {number} imageIndex - Index of the image (1, 2, 3, etc.)
 * @param {boolean} isMainImage - Whether this is the main image (true) or thumbnail (false)
 * @returns {Promise<string>} - Cloudinary URL
 */
async function uploadImageToCloudinary(base64Image, productName, imageIndex = 1, isMainImage = false) {
  try {
    // Remove the data URL prefix if present
    const base64Data = base64Image.replace(/^data:image\/[a-z]+;base64,/, '');
    
    // Create a unique public ID for the image
    const publicId = `plwg-creative-apparel/${productName.toLowerCase().replace(/[^a-z0-9]/g, '-')}/image-${imageIndex}`;
    
    console.log(`☁️ Uploading image ${imageIndex} to Cloudinary for product: ${productName} (${isMainImage ? 'MAIN' : 'THUMBNAIL'})`);
    
    // Upload original asset without transformations so we can derive
    // high-quality, size-appropriate variants on delivery
    const result = await cloudinary.uploader.upload(
      base64Image, // Use the original base64 data URL
      {
        public_id: publicId,
        folder: 'plwg-creative-apparel',
        resource_type: 'image',
        overwrite: true,
        use_filename: false,
        timeout: 180000, // 3 minutes timeout for uploads
        chunk_size: 6000000 // 6MB chunks for large images
      }
    );
    
    console.log(`✅ Image ${imageIndex} uploaded successfully: ${result.secure_url} (${isMainImage ? 'MAIN' : 'THUMBNAIL'})`);
    return result.secure_url;
    
  } catch (error) {
    console.error(`❌ Error uploading image ${imageIndex} to Cloudinary:`, error);
    throw error;
  }
}

/**
 * Upload multiple images for a product
 * @param {Array} images - Array of base64 image data
 * @param {string} productName - Name of the product
 * @returns {Promise<Object>} - Object with main image URL and sub image URLs
 */
async function uploadProductImages(images, productName) {
  const uploadedUrls = {
    mainImage: null,
    subImages: []
  };
  
  if (!images || images.length === 0) {
    console.log('⚠️ No images provided for upload');
    return uploadedUrls;
  }
  
  try {
    console.log(`📸 Starting upload of ${images.length} images for product: ${productName}`);
    
    // Upload main image (first image)
    if (images[0] && images[0].data) {
      uploadedUrls.mainImage = await uploadImageToCloudinary(images[0].data, productName, 1, true);
    }
    
    // Upload sub images (additional images)
    const uploadPromises = [];
    for (let i = 1; i < images.length && i < 5; i++) {
      if (images[i] && images[i].data) {
        uploadPromises.push(
          uploadImageToCloudinary(images[i].data, productName, i + 1, false)
            .then(url => uploadedUrls.subImages.push(url))
        );
      }
    }
    
    // Wait for all sub images to upload
    if (uploadPromises.length > 0) {
      await Promise.all(uploadPromises);
    }
    
    console.log(`🎉 All images uploaded successfully for product: ${productName}`);
    console.log(`📊 Main image: ${uploadedUrls.mainImage}`);
    console.log(`📊 Sub images: ${uploadedUrls.subImages.length} uploaded`);
    
    return uploadedUrls;
    
  } catch (error) {
    console.error('❌ Error uploading product images:', error);
    throw error;
  }
}

/**
 * Delete images from Cloudinary (for when products are deleted)
 * @param {Array} imageUrls - Array of Cloudinary URLs to delete
 */
async function deleteImagesFromCloudinary(imageUrls) {
  if (!imageUrls || imageUrls.length === 0) {
    return;
  }
  
  try {
    console.log(`🗑️ Deleting ${imageUrls.length} images from Cloudinary`);
    
    const deletePromises = imageUrls.map(async (url) => {
      try {
        // Extract public ID from URL
        const publicId = url.split('/').slice(-2).join('/').replace(/\.[^/.]+$/, '');
        await cloudinary.uploader.destroy(publicId);
        console.log(`✅ Deleted image: ${publicId}`);
      } catch (error) {
        console.error(`❌ Error deleting image: ${url}`, error);
      }
    });
    
    await Promise.all(deletePromises);
    console.log('✅ All images deleted from Cloudinary');
    
  } catch (error) {
    console.error('❌ Error deleting images from Cloudinary:', error);
  }
}

module.exports = {
  uploadImageToCloudinary,
  uploadProductImages,
  deleteImagesFromCloudinary
}; 