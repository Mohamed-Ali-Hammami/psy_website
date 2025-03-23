from flask import request, jsonify
import json
from typing import Dict, Any, Optional
from .db_setup import get_db_connection
import logging
class TermsOfServiceManager:
    def __init__(self, connection):
        self.connection = connection

    def get_terms_text(self, language: str = 'en') -> Optional[str]:
        query = "SELECT content FROM terms_and_services WHERE language = %s LIMIT 1"
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (language,))
                result = cursor.fetchone()
                return result['content'] if result else None
        except Exception as e:
            return None

    def update_terms(self, content: str, language: str = 'en') -> Optional[Dict[str, Any]]:
        logging.info(f"Updating terms content for language: {language}")
        try:
            # Only update content based on the language
            query = """
                UPDATE terms_and_services
                SET content = %s
                WHERE language = %s
            """
            with self.connection.cursor() as cursor:
                cursor.execute(query, (content, language))
                self.connection.commit()
                logging.info(f"Content updated successfully")
                return {'success': True, 'message': 'Terms updated successfully'}
        except Exception as e:
            logging.error(f"Error updating terms: {e}")
            self.connection.rollback()
            return {'success': False, 'message': 'Error updating terms'}

    def create_terms(self, title: str, content: str, language: str = 'en') -> Optional[Dict[str, Any]]:
        try:
            with self.connection.cursor() as cursor:
                cursor.callproc('ManageTermsAndServices', [
                    'CREATE', None, title, content, language
                ])
                result = None
                for result_set in cursor.stored_results():
                    result = result_set.fetchone()
                self.connection.commit()
                return result
        except Exception as e:
            self.connection.rollback()
            return None

    def search_terms(self, search_term: str) -> Optional[list]:
        try:
            with self.connection.cursor() as cursor:
                cursor.callproc('ManageTermsAndServices', [
                    'SEARCH', None, search_term, None, None
                ])
                results = []
                for result_set in cursor.stored_results():
                    results = result_set.fetchall()
                return results
        except Exception as e:
            return None
def manage_terms():
    try:
        connection = get_db_connection()

        tos_manager = TermsOfServiceManager(connection)
        
        # Handle GET requests
        if request.method == 'GET':
            action = request.args.get('action', 'text')
            if action == 'text':
                language = request.args.get('language', 'en')
                terms_text = tos_manager.get_terms_text(language=language)
                if terms_text:
                    return terms_text
                else:
                    return "Terms not found", 404
            elif action == 'search':
                search_term = request.args.get('q', '')
                search_results = tos_manager.search_terms(search_term)
                if search_results:
                    return json.dumps(search_results)  # Ensure it's serialized properly
                else:
                    return "No terms found", 404

        # Handle POST requests for creating terms
        elif request.method == 'POST':
            data = request.get_json()
            if not all(key in data for key in ['title', 'content']):
                return jsonify({'success': False, 'message': 'Title and content are required'}), 400

            result = tos_manager.create_terms(title=data['title'], content=data['content'], language=data.get('language', 'en'))
            if result:
                return jsonify({'success': True, 'result': result}), 201
            else:
                return jsonify({'success': False, 'message': 'Error creating terms'}), 500

        # Handle PUT requests for updating terms (only update content)
        elif request.method == 'PUT':
            data = request.get_json()
            if not 'content' in data:
                return jsonify({'success': False, 'message': 'Content is required'}), 400

            result = tos_manager.update_terms(content=data['content'], language=data.get('language', 'en'))
            if result['success']:
                return jsonify({'success': True, 'result': result}), 200
            else:
                return jsonify({'success': False, 'message': result['message']}), 500

    except Exception as e:
        logging.error(f"Error in manage_terms: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        connection.close()
        logging.info("Database connection closed")
