import { extname, join } from 'path';
import { existsSync, mkdirSync } from 'fs';
import { diskStorage } from 'multer';
import { BadRequestException } from '@nestjs/common';

export const imageMulterOptions = (folder: string) => ({
  storage: diskStorage({
    destination: (_req, _file, cb) => {
      const uploadPath = join(process.cwd(), 'uploads', folder);
      if (!existsSync(uploadPath)) mkdirSync(uploadPath, { recursive: true });
      cb(null, uploadPath);
    },
    filename: (_req, file, cb) => {
      const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
      cb(null, unique + extname(file.originalname).toLowerCase())
    },
  }),
  fileFilter: (_req, file, cb) => {
    if (!/^image\/(jpg|jpeg|png|gif|webp)$/i.test(file.mimetype)) {
      return cb(new BadRequestException('Chỉ cho phép file ảnh JPG, JPEG, PNG, GIF, WEBP'), false);
    }
    cb(null, true);
  },
  limits: { fileSize: 5 * 1024 * 1024 },
});
