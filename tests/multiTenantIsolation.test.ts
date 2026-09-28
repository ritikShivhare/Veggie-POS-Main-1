import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  authMiddleware,
  sessionService,
  orderRepo,
  customerRepo,
  staffRepo,
  ingredientRepo,
  purchaseRepo,
  recipeRepo
} from "../server/context";
import { Database, CrossTenantViolationError } from "../server/features/shared/database";
import { syncService } from "../server/context";

describe("Strict Multi-Tenant Isolation Tests (Restaurant A vs Restaurant B)", () => {
  const db = Database.getInstance();
  const tenantA = "restaurant-a-delhi";
  const tenantB = "restaurant-b-mumbai";

  let mockReq: any;
  let mockRes: any;
  let nextFn: any;

  beforeEach(async () => {
    vi.restoreAllMocks();

    mockReq = {
      headers: {},
      query: {},
      body: {},
      params: {},
      cookies: {}
    };

    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis()
    };

    nextFn = vi.fn();

    // Seed distinct data for Restaurant A and Restaurant B
    await orderRepo.saveAll(tenantA, [
      { id: "ord-a-101", orderNumber: 101, total: 250, status: "Completed", date: "2026-09-28" } as any
    ]);
    await orderRepo.saveAll(tenantB, [
      { id: "ord-b-999", orderNumber: 999, total: 1200, status: "Completed", date: "2026-09-28" } as any
    ]);

    await customerRepo.saveAll(tenantA, [
      { id: "cust-a-01", name: "Customer A", phone: "9999900001", totalSpent: 250, visitCount: 1 } as any
    ]);
    await customerRepo.saveAll(tenantB, [
      { id: "cust-b-99", name: "Customer B Secret", phone: "8888800009", totalSpent: 5000, visitCount: 10 } as any
    ]);

    await staffRepo.saveAll(tenantA, [
      { id: "staff-a-01", name: "Chef Mohan (A)", role: "Chef", pin: "3333" } as any
    ]);
    await staffRepo.saveAll(tenantB, [
      { id: "staff-b-99", name: "Secret Manager (B)", role: "Manager", pin: "2222" } as any
    ]);

    await ingredientRepo.saveAll(tenantA, [
      { id: "ing-a-01", name: "Paneer A", currentStock: 10, unit: "kg" } as any
    ]);
    await ingredientRepo.saveAll(tenantB, [
      { id: "ing-b-99", name: "Saffron Secret B", currentStock: 50, unit: "g" } as any
    ]);

    await purchaseRepo.saveAll(tenantA, [
      { id: "purch-a-01", invoiceNumber: "INV-A-1", totalAmount: 400 } as any
    ]);
    await purchaseRepo.saveAll(tenantB, [
      { id: "purch-b-99", invoiceNumber: "INV-B-SECRET", totalAmount: 85000 } as any
    ]);
  });

  describe("Server-Determined Identity & Repository Scoping", () => {
    it("should never return Restaurant B order data when querying under Restaurant A context", async () => {
      // Restaurant A tries to fetch Restaurant B's order ID
      const order = await orderRepo.getById(tenantA, "ord-b-999");
      expect(order).toBeNull();

      // Only Restaurant A's own orders should be visible
      const ownOrder = await orderRepo.getById(tenantA, "ord-a-101");
      expect(ownOrder).not.toBeNull();
      expect(ownOrder?.id).toBe("ord-a-101");
      expect(ownOrder?.total).toBe(250);
    });

    it("should never return Restaurant B customer data when querying under Restaurant A context", async () => {
      const customer = await customerRepo.getById(tenantA, "cust-b-99");
      expect(customer).toBeNull();

      const ownCustomer = await customerRepo.getById(tenantA, "cust-a-01");
      expect(ownCustomer).not.toBeNull();
      expect(ownCustomer?.name).toBe("Customer A");
    });

    it("should never return Restaurant B staff data when querying under Restaurant A context", async () => {
      const staffMember = await staffRepo.getById(tenantA, "staff-b-99");
      expect(staffMember).toBeNull();

      const ownStaff = await staffRepo.getById(tenantA, "staff-a-01");
      expect(ownStaff).not.toBeNull();
      expect(ownStaff?.name).toBe("Chef Mohan (A)");
    });

    it("should never return Restaurant B inventory data when querying under Restaurant A context", async () => {
      const ingredient = await ingredientRepo.getById(tenantA, "ing-b-99");
      expect(ingredient).toBeNull();

      const purchase = await purchaseRepo.getById(tenantA, "purch-b-99");
      expect(purchase).toBeNull();

      const ownIng = await ingredientRepo.getById(tenantA, "ing-a-01");
      expect(ownIng).not.toBeNull();
      expect(ownIng?.name).toBe("Paneer A");
    });
  });

  describe("Anti-Spoofing authMiddleware Tenant Isolation", () => {
    it("should reject with 403 TENANT_MISMATCH when Restaurant A session sends Restaurant B tenantId in query", async () => {
      const sessionA = await sessionService.createSession(
        tenantA,
        "user-a-01",
        "Owner A",
        "Owner",
        "127.0.0.1",
        "TestAgent",
        ["billing", "inventory", "reports", "settings"]
      );

      mockReq.headers["x-session-id"] = sessionA.sessionId;
      mockReq.query.tenantId = tenantB; // Attempting to spoof Restaurant B

      await authMiddleware(mockReq, mockRes, nextFn);

      expect(nextFn).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: "TENANT_MISMATCH"
        })
      );
    });

    it("should reject with 403 TENANT_MISMATCH when Restaurant A session sends Restaurant B tenantId in headers", async () => {
      const sessionA = await sessionService.createSession(
        tenantA,
        "user-a-01",
        "Owner A",
        "Owner",
        "127.0.0.1",
        "TestAgent",
        ["billing", "inventory", "reports", "settings"]
      );

      mockReq.headers["x-session-id"] = sessionA.sessionId;
      mockReq.headers["x-tenant-id"] = tenantB; // Attempting header spoof

      await authMiddleware(mockReq, mockRes, nextFn);

      expect(nextFn).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: "TENANT_MISMATCH"
        })
      );
    });

    it("should reject with 403 TENANT_MISMATCH when Restaurant A session sends Restaurant B tenantId in request body", async () => {
      const sessionA = await sessionService.createSession(
        tenantA,
        "user-a-01",
        "Owner A",
        "Owner",
        "127.0.0.1",
        "TestAgent",
        ["billing", "inventory", "reports", "settings"]
      );

      mockReq.headers["x-session-id"] = sessionA.sessionId;
      mockReq.body = { tenantId: tenantB, someField: "test" };

      await authMiddleware(mockReq, mockRes, nextFn);

      expect(nextFn).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: "TENANT_MISMATCH"
        })
      );
    });

    it("should reject with 403 TENANT_MISMATCH when Restaurant A session sends nested alien tenantId in body array", async () => {
      const sessionA = await sessionService.createSession(
        tenantA,
        "user-a-01",
        "Owner A",
        "Owner",
        "127.0.0.1",
        "TestAgent",
        ["billing", "inventory", "reports", "settings"]
      );

      mockReq.headers["x-session-id"] = sessionA.sessionId;
      mockReq.body = [
        { id: "item-1", tenantId: tenantB }
      ];

      await authMiddleware(mockReq, mockRes, nextFn);

      expect(nextFn).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: "TENANT_MISMATCH"
        })
      );
    });
  });

  describe("Database RLS & Schema Cache Integrity", () => {
    it("should reject saveSlice with CrossTenantViolationError if any row has alien tenantId", async () => {
      const alienData = [
        { id: "ing-malicious", name: "Injected Item", tenantId: tenantB }
      ];

      await expect(
        db.saveSlice(tenantA, "ingredients", alienData as any[])
      ).rejects.toThrow(CrossTenantViolationError);
    });

    it("should never inject 'pin' column onto ingredients or non-staff slices during state sync", async () => {
      const fullState = {
        ingredients: [
          { id: "ing-fresh-01", name: "Fresh Coriander", currentStock: 5, unit: "kg" }
        ],
        recipes: [],
        menuItems: [
          { id: "m-burger-01", name: "Vegan Burger", price: 180, category: "Burgers" }
        ],
        staffList: [
          { id: "staff-1", name: "Admin", role: "Owner", pin: "1111" }
        ],
        orders: [],
        customers: [],
        purchases: [],
        shifts: [],
        settings: { restaurantName: "Test Resto" }
      };

      const result = await syncService.saveFullState(tenantA, fullState as any);
      expect(result).toBeDefined();

      // Verify that ingredients in saved full state has NO pin property
      const savedIngredients = await ingredientRepo.getAll(tenantA);
      expect(savedIngredients).toBeDefined();
      expect(savedIngredients?.length).toBeGreaterThan(0);
      for (const ing of savedIngredients || []) {
        expect("pin" in ing).toBe(false);
      }

      // Verify that menu items has NO pin property
      const savedMenuItems = await db.getSlice(tenantA, "menuItems");
      for (const menu of (savedMenuItems as any[]) || []) {
        expect("pin" in menu).toBe(false);
      }
    });
  });
});
