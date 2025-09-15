export class CreateCoinPackageDto {
  packageId: string;
  name: string;
  coinsAmount: number;
  price: number;
  currency?: string;
}
