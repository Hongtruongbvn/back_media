import { MongoClient } from 'mongodb';
import * as fs from 'fs';

async function exportAllSchemas() {
  // Sử dụng biến môi trường hoặc connection string trực tiếp
  const uri =
    process.env.MONGODB_URI || 'mongodb://localhost:27017/SocialMediaAppDEMO';
  const client = new MongoClient(uri);

  try {
    await client.connect();
    const db = client.db();
    const collections = await db.listCollections().toArray();

    let allSchemas = {};

    for (let col of collections) {
      const collection = db.collection(col.name);
      const sampleDocs = await collection.find().limit(5).toArray();

      // Phân tích schema
      const schema = {};
      sampleDocs.forEach((doc) => {
        Object.keys(doc).forEach((key) => {
          if (!schema[key]) {
            schema[key] = {
              type: getType(doc[key]),
              frequency: 1,
            };
          } else {
            schema[key].frequency++;
          }
        });
      });

      allSchemas[col.name] = schema;
    }

    fs.writeFileSync(
      'mongodb-schemas.json',
      JSON.stringify(allSchemas, null, 2),
    );
    console.log('✅ Exported schemas to mongodb-schemas.json');
  } catch (error) {
    console.error('❌ Error exporting schemas:', error);
  } finally {
    await client.close();
  }
}

function getType(value: any): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (value instanceof Date) return 'date';
  return typeof value;
}

// Chạy function
exportAllSchemas();
