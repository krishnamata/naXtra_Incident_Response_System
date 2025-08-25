from flask import request, render_template, Blueprint
from sqlalchemy import or_
from app.utils.rule_index import RuleIndex

# Define the Blueprint here before using it
search_bp = Blueprint('search', __name__)

@search_bp.route('/user/search', methods=['GET', 'POST'])
def search_view():
    # Determine search type (rules or decoders)
    # Priority: POST form data, then GET query params, default to 'rule'
    search_type = request.form.get('search_type', request.args.get('search_type', 'rule'))
    
    # Get the search query string from POST or GET parameters
    search_query = request.form.get('search_query', request.args.get('search_query', '')).strip()
    
    # Pagination: get current page number from query params, default to 1
    page = request.args.get('page', 1, type=int)
    
    # Number of items per page
    per_page = 20

           # If search_type is 'rule', include all known rule-related types
    # such as 'linux', 'winlogbeat', 'custom', etc. to ensure broader matching.
    # This allows users to find rules regardless of their specific subtype.
    # For other types (e.g., 'decoder'), apply exact filtering.

    if search_type == 'rule':
        query = RuleIndex.query.filter(RuleIndex.type.in_(['rule', 'linux', 'winlogbeat', 'custom', 'hp', 'windows', 'cisco']))
    else:
        query = RuleIndex.query.filter_by(type=search_type)


    # Check if rule_id is given in GET parameters (direct link to specific rule)
    if search_query:
        query = query.filter(
            or_(
                RuleIndex.rule_id.ilike(f"%{search_query}%"),
                RuleIndex.keywords.ilike(f"%{search_query}%")
            )
        )


    # for debug purpose
    #print("DEBUG: search_query =", search_query)
    #print("DEBUG: Matching Rule IDs:")
    #for r in RuleIndex.query.all():
        #print(r.rule_id)



    # Order the results by rule_id ascending (numerical order if rule_id is numeric)
    query = query.order_by(RuleIndex.rule_id.asc())

    # Paginate the query result: fetch current page with per_page items
    # error_out=False prevents 404 on invalid page numbers
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Extract the items to pass to template
    results = pagination.items

    # Render the search view template with results and pagination metadata
    return render_template(
        'search_view.html',
        results=results,
        search_type=search_type,
        search_query=search_query,
        pagination=pagination
    )
