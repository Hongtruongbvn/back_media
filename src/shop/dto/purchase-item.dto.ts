import { IsMongoId, IsNotEmpty, IsString } from 'class-validator';

export class PurchaseItemDto {
  @IsNotEmpty()
  @IsString()
  @IsMongoId()
  itemId: string;
}
