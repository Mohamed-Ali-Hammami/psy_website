from db_setup import get_db_connection
import logging

def purchase_product(user_id, product_name, session_id, price):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM purchases WHERE session_id = %s AND product_name = %s",
                (session_id, product_name)
            )
            existing_purchase = cursor.fetchone()
            
            if existing_purchase:
                print(f"Purchase already recorded for session {session_id}")
                return True
            cursor.execute(
                "INSERT INTO purchases (user_id, product_name, session_id, price) VALUES (%s, %s, %s, %s)",
                (user_id, product_name, session_id, price)
            )
            connection.commit()
            return True
    except Exception as e:
        connection.rollback()
        print(f"Error during purchase: {e}")
        return False
    finally:
        connection.close()

def get_purchases_by_session_id(session_id):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.callproc('GetPurchasesBySessionID', (session_id,))
            result = cursor.fetchall()
            purchases = [{
                'purchase_id': purchase['purchase_id'],
                'product_name': purchase['product_name'],
                'purchased_at': purchase['purchased_at'],
                'price': purchase['price']
            } for purchase in result] if result else []
            logging.info(f"Purchases for session {session_id} retrieved: {purchases}")
            return purchases
    except Exception as e:
        logging.error(f"Error fetching purchases for session {session_id}: {e}")
        return []
    finally:
        connection.close()
def get_purchases_by_user_id(user_id):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.callproc('GetPurchasesByUserID', (user_id,))
            result = cursor.fetchall()
            purchases = [{
                'purchase_id': purchase['purchase_id'],
                'product_name': purchase['product_name'],
                'purchased_at': purchase['purchased_at'],
                'price': purchase['price']
            } for purchase in result] if result else []
            logging.info(f"Purchases for user {user_id} retrieved: {purchases}")
            return purchases
    except Exception as e:
        logging.error(f"Error fetching purchases for user {user_id}: {e}")
        return []
    finally:
        connection.close()
